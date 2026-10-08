"""rbac.store.list_roles_for_permission 按权限反查角色的回归测试。

list-permission-roles 反查直接获授角色时，用该函数直接读取规则库。
本测试不经过命令行子进程，直接传入权限名调用存储层函数，使用真实
SQLite 数据核对反查语义。覆盖范围：

- 固定样例：reader 获授 documents:read、documents:write，editor 获授
  documents:read，ghost 仅获授 reports:export；反查 documents:read
  恰好返回 ["editor", "reader"]，反查 documents:write 返回 ["reader"]，
  反查未授予权限返回 []；editor 未绑定任何固定成员仍进入结果，ghost 的
  其他权限不得混入；
- 精确匹配：函数按传入原值大小写敏感匹配权限名，不替调用方去除首尾空白，
  给读取权限名添加首尾空白或改变大小写都返回 []；"*"、"%"、"_" 均为
  普通字符，仅匹配相同完整名称；
- 名称原样保留、去重与 Unicode 码点排序：在只含 role、permission 两个
  文本列且允许重复行的规则表中，给 A、a、中 三个角色保存同一权限并
  重复一行，结果仍为 ["A", "a", "中"]；
- 查询只读且结果稳定：重复调用结果一致，调用前后全部授权记录不变；
- 区分空结果与存储失败：现存 role_permissions 表只有 role 列、缺少
  permission 列并保存一行 reader 时，传入有效权限查询抛出
  rbac.store.StorageError，不能返回 []，也不得直接抛出 sqlite3 原始
  异常；失败后原有表结构与记录保持不变。

只依赖 Python 3 标准库与 SQLite；每个用例使用独立临时数据库文件，
连接在用例结束时关闭释放，不依赖任何已有规则文件或其他用例的执行顺序。
从项目根目录执行：

    python -m unittest discover -s tests -p test_roles_for_permission_store.py
"""

import os
import sqlite3
import sys
import tempfile
import unittest

# tests/ 的上一级即项目根目录（rbac 包所在目录）。
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from rbac import store

PERMISSION_READ = "documents:read"
PERMISSION_WRITE = "documents:write"
PERMISSION_EXPORT = "reports:export"

# 固定样例规则库：
# reader 持有 documents:read、documents:write；
# editor 只持有 documents:read（固定成员配置中没有任何成员绑定 editor）；
# ghost 仅持有 reports:export，与两个 documents 权限无关。
SEED_RULES = (
    ("reader", PERMISSION_READ),
    ("reader", PERMISSION_WRITE),
    ("editor", PERMISSION_READ),
    ("ghost", PERMISSION_EXPORT),
)

# 允许重复行的规则表：只有两个文本列，没有主键或唯一约束。
_DUPLICATE_ALLOWED_SCHEMA = (
    "CREATE TABLE role_permissions (role TEXT, permission TEXT)"
)

# 不兼容的表结构：只有 role 列，缺少 permission 列。
_INCOMPATIBLE_SCHEMA = "CREATE TABLE role_permissions (role TEXT)"


class RolesForPermissionTests(unittest.TestCase):
    """在固定样例规则库上核对按权限反查角色的结果语义。"""

    def setUp(self):
        # 每个用例独立的临时目录与数据库文件，TemporaryDirectory.cleanup
        # 负责清理；连接在用例结束时关闭释放。
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.db_path = os.path.join(self._tmpdir.name, "rules.db")
        self.conn = store.connect(self.db_path)
        self.addCleanup(self.conn.close)
        for role, permission in SEED_RULES:
            self.assertTrue(
                store.grant_permission(self.conn, role, permission),
                f"测试前置：预置规则 {role}/{permission} 应实际新增",
            )

    # ---- 辅助方法 -------------------------------------------------------

    def stored_rules(self):
        """直接读取 SQLite，返回排序后的 (role, permission) 授权记录。"""
        return sorted(
            self.conn.execute(
                "SELECT role, permission FROM role_permissions"
            ).fetchall()
        )

    def assert_roles(self, permission, expected, context):
        """核对反查结果，并验证查询只读、结果稳定、不改授权记录。

        同一查询连续执行两次，结果必须一致；调用前后完整授权记录不得
        变化。权限名按传入原值原样使用，不做规整。
        """
        rules_before = self.stored_rules()

        first = store.list_roles_for_permission(self.conn, permission)
        second = store.list_roles_for_permission(self.conn, permission)

        self.assertEqual(
            first,
            expected,
            f"{context}：期望 {expected!r}，实际为 {first!r}",
        )
        self.assertEqual(
            second,
            first,
            f"{context}：重复调用结果应稳定，第一次 {first!r}，"
            f"第二次 {second!r}",
        )
        self.assertEqual(
            self.stored_rules(),
            rules_before,
            f"{context}：查询不应改动授权记录，之前 {rules_before!r}，"
            f"之后 {self.stored_rules()!r}",
        )

    # ---- 固定样例反查结果 -----------------------------------------------

    def test_read_permission_returns_editor_and_reader_exactly(self):
        result = store.list_roles_for_permission(self.conn, PERMISSION_READ)
        self.assertEqual(
            result,
            ["editor", "reader"],
            f"反查 documents:read 应恰好返回 editor、reader，"
            f"实际为 {result!r}",
        )
        # 钉死“恰好”：不多一项（ghost 不持有该权限），不少一项，也无重复。
        self.assertEqual(
            len(result),
            2,
            f"反查结果应恰好含 2 个角色，实际为 {result!r}",
        )
        self.assertEqual(
            len(result),
            len(set(result)),
            f"反查结果中不得有重复角色，实际为 {result!r}",
        )
        self.assertNotIn(
            "ghost",
            result,
            f"ghost 不持有 documents:read，不得混入结果，实际为 {result!r}",
        )
        # editor 没有绑定任何固定成员，但直接授权反查只看规则库，
        # 不依赖成员配置，editor 仍必须出现在结果中。
        self.assertIn(
            "editor",
            result,
            f"未绑定固定成员的 editor 仍应进入结果，实际为 {result!r}",
        )
        # 按 Unicode 码点升序：editor < reader。
        self.assertEqual(
            result,
            sorted(result),
            f"角色应按 Unicode 码点升序排列，实际为 {result!r}",
        )

    def test_write_permission_returns_only_reader(self):
        # documents:write 只授给了 reader，editor 与 ghost 均不持有。
        self.assert_roles(
            PERMISSION_WRITE, ["reader"], "反查 documents:write"
        )

    def test_ungranted_permission_returns_empty_list(self):
        # 该权限从未授予任何角色：正常空结果，而非存储失败。
        self.assert_roles(
            "accounts:delete",
            [],
            "反查从未授予的 accounts:delete",
        )
        # 与已授权名称前缀相似但不完整的名称同样为空。
        self.assert_roles(
            "documents:re",
            [],
            "反查前缀相似但不完整的 documents:re",
        )

    def test_ghost_other_permission_is_not_mixed_in(self):
        # ghost 仅持有 reports:export：反查该权限只得到 ghost，
        # 反查 documents 系列权限时 ghost 一律不出现。
        self.assert_roles(
            PERMISSION_EXPORT,
            ["ghost"],
            "反查 reports:export",
        )
        read_result = store.list_roles_for_permission(self.conn, PERMISSION_READ)
        self.assertNotIn(
            "ghost",
            read_result,
            f"ghost 的 reports:export 不得混入 documents:read 结果，"
            f"实际为 {read_result!r}",
        )
        write_result = store.list_roles_for_permission(self.conn, PERMISSION_WRITE)
        self.assertNotIn(
            "ghost",
            write_result,
            f"ghost 的 reports:export 不得混入 documents:write 结果，"
            f"实际为 {write_result!r}",
        )

    # ---- 精确匹配：不裁剪空白、大小写敏感 -------------------------------

    def test_surrounding_whitespace_is_not_trimmed(self):
        # 存储层不替调用方去除首尾空白：带空白的名称与原名是不同权限，
        # 样例中没有任何角色持有这些名称，必须返回 []。
        for permission in (
            " " + PERMISSION_READ,
            PERMISSION_READ + " ",
            "\t" + PERMISSION_READ + "\n",
            " " + PERMISSION_READ + " ",
        ):
            with self.subTest(permission=permission):
                self.assert_roles(
                    permission,
                    [],
                    f"反查带首尾空白的权限名 {permission!r}",
                )

        # 对照：不带空白的原值仍正常命中，证明空结果确实来自精确匹配。
        self.assert_roles(
            PERMISSION_READ,
            ["editor", "reader"],
            "对照：反查不带空白的原值",
        )

    def test_permission_matching_is_case_sensitive(self):
        for permission in (
            "DOCUMENTS:READ",
            "Documents:Read",
            "documents:READ",
        ):
            with self.subTest(permission=permission):
                self.assert_roles(
                    permission,
                    [],
                    f"反查大小写不同的权限名 {permission!r}",
                )

    # ---- "*"、"%"、"_" 按普通字符精确匹配 -------------------------------

    def test_wildcard_chars_are_literal_and_match_full_name_only(self):
        # 直接把 "*"、"%"、"_" 以及含这些字符的名称作为普通权限名授予。
        literal_rules = (
            ("star", "*"),
            ("percent", "%"),
            ("underscore", "_"),
            ("reader", "docs:*_%read"),
        )
        for role, permission in literal_rules:
            self.assertTrue(
                store.grant_permission(self.conn, role, permission),
                f"测试前置：预置规则 {role}/{permission} 应实际新增",
            )

        # 只有完全相同的完整名称才命中。
        self.assert_roles("*", ["star"], "反查权限名 *")
        self.assert_roles("%", ["percent"], "反查权限名 %")
        self.assert_roles("_", ["underscore"], "反查权限名 _")
        self.assert_roles(
            "docs:*_%read",
            ["reader"],
            "反查含通配字符的完整权限名",
        )

        # 任何把这些字符当作通配符的“模糊匹配”都必须落空：
        # 不同字符、不同长度、仅大小写不同的名称均不命中。
        for other in (
            "**",
            "%%",
            "__",
            "a",
            "docs:%read",
            "docs:*_read",
            "docs:X_%read",
            "docs:*_%READ",
            "docs:*_%read ",
        ):
            with self.subTest(other=other):
                self.assert_roles(
                    other,
                    [],
                    f"反查名称 {other!r} 不应模糊命中",
                )

    # ---- 去重、Unicode 码点排序与原名保留（允许重复行的表）--------------

    def test_duplicate_rows_are_deduped_and_names_preserved(self):
        # 独立样例库：表只有 role、permission 两个文本列，无主键，
        # 允许同一 (role, permission) 保存多行。
        dup_db = os.path.join(self._tmpdir.name, "duplicate_rules.db")
        with sqlite3.connect(dup_db) as raw_conn:
            raw_conn.execute(_DUPLICATE_ALLOWED_SCHEMA)
            # 故意按与码点顺序不同的次序写入，并把 ("A", read) 重复一行。
            raw_conn.executemany(
                "INSERT INTO role_permissions (role, permission) VALUES (?, ?)",
                [
                    ("中", PERMISSION_READ),
                    ("A", PERMISSION_READ),
                    ("a", PERMISSION_READ),
                    ("A", PERMISSION_READ),
                ],
            )
            raw_conn.commit()

        # connect 的 CREATE TABLE IF NOT EXISTS 对已有表为空操作，
        # 不补主键、不删除重复行。
        conn = store.connect(dup_db)
        self.addCleanup(conn.close)

        result = store.list_roles_for_permission(conn, PERMISSION_READ)
        # 重复行被去重，名称原样保留（大小写、中文字符不转换），
        # 按 Unicode 码点升序：A(0x41) < a(0x61) < 中(0x4E2D)。
        self.assertEqual(
            result,
            ["A", "a", "中"],
            f"重复行应去重并按 Unicode 码点升序返回原名，实际为 {result!r}",
        )

        # 重复查询结果一致，且去重只是查询行为：表里的 4 行（含重复行）
        # 在查询前后保持不变。
        self.assertEqual(
            store.list_roles_for_permission(conn, PERMISSION_READ),
            result,
            "允许重复行的样例上重复查询结果应一致",
        )
        surviving_rows = sorted(
            conn.execute(
                "SELECT role, permission FROM role_permissions"
            ).fetchall()
        )
        self.assertEqual(
            surviving_rows,
            [
                ("A", PERMISSION_READ),
                ("A", PERMISSION_READ),
                ("a", PERMISSION_READ),
                ("中", PERMISSION_READ),
            ],
            f"查询不得删除重复行或改写记录，实际为 {surviving_rows!r}",
        )

    # ---- 查询只读：全部授权记录不变 -------------------------------------

    def test_queries_do_not_modify_seed_rules(self):
        # 对主样例库执行各类查询（命中、未命中、带空白、改大小写）后，
        # 完整授权记录应与预置完全一致。
        for permission in (
            PERMISSION_READ,
            PERMISSION_WRITE,
            PERMISSION_EXPORT,
            "accounts:delete",
            " " + PERMISSION_READ,
            "DOCUMENTS:READ",
        ):
            with self.subTest(permission=permission):
                store.list_roles_for_permission(self.conn, permission)

        self.assertEqual(
            self.stored_rules(),
            sorted(SEED_RULES),
            f"全部查询后授权记录应与预置一致，实际为 {self.stored_rules()!r}",
        )


class RolesForPermissionIncompatibleSchemaTests(unittest.TestCase):
    """缺少 permission 列的现存规则表：存储失败不得退化为空结果。"""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.db_path = os.path.join(self._tmpdir.name, "rules.db")
        # 准备测试输入：表只有 role 列并保存一行 reader。
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(_INCOMPATIBLE_SCHEMA)
            conn.execute("INSERT INTO role_permissions (role) VALUES ('reader')")
        # connect 的 CREATE TABLE IF NOT EXISTS 对已有表为空操作，不补列。
        self.conn = store.connect(self.db_path)
        self.addCleanup(self.conn.close)

    def stored_state(self):
        """直接读取 SQLite，返回 (建表语句, 列定义, 全部行)。"""
        schema = self.conn.execute(
            "SELECT sql FROM sqlite_master WHERE name = 'role_permissions'"
        ).fetchone()[0]
        columns = self.conn.execute(
            "PRAGMA table_info(role_permissions)"
        ).fetchall()
        rows = sorted(self.conn.execute("SELECT role FROM role_permissions").fetchall())
        return schema, columns, rows

    def assert_state_unchanged(self, state_before, context):
        """调用后列定义与 reader 数据应与调用前一致：不补列、不改记录。"""
        state_after = self.stored_state()
        self.assertEqual(
            state_after,
            state_before,
            f"{context}：调用后表结构或数据发生变化，调用前为 {state_before!r}，"
            f"调用后为 {state_after!r}",
        )
        # 显式钉死：列定义里不得新增 permission 列。
        self.assertEqual(
            [column[1] for column in state_after[1]],
            ["role"],
            f"{context}：列定义应仍只有 role，"
            f"实际为 {[column[1] for column in state_after[1]]!r}",
        )
        # 显式钉死：预置的 reader 行既不被删除，也不被补写。
        self.assertEqual(
            state_after[2],
            [("reader",)],
            f"{context}：reader 数据应保持不变，实际为 {state_after[2]!r}",
        )

    def test_valid_permission_query_raises_storage_error(self):
        state_before = self.stored_state()
        self.assertEqual(
            state_before,
            (_INCOMPATIBLE_SCHEMA, [(0, "role", "TEXT", 0, None, 0)], [("reader",)]),
            f"测试前置：表应只有 role 列并保存一行 reader，实际为 {state_before!r}",
        )

        # 传入有效的权限名（该名称在结构正常的样例库中本应命中 reader、
        # editor）：缺列导致存储失败，必须抛出 rbac.store.StorageError，
        # 而非返回 [] 把失败伪装成“权限未授予”的正常空结果。
        with self.assertRaises(
            store.StorageError,
            msg="缺少 permission 列时有效权限查询应抛出 StorageError",
        ) as assertion_context:
            store.list_roles_for_permission(self.conn, PERMISSION_READ)

        # 不得直接向外抛出 sqlite3 原始异常：StorageError 不是 sqlite3.Error，
        # 且其 __cause__ 中的底层 sqlite3 错误已被包装而非直通。
        raised = assertion_context.exception
        self.assertNotIsInstance(
            raised,
            sqlite3.Error,
            f"对外抛出的应是包装后的 StorageError，而非 sqlite3 原始异常，"
            f"实际类型为 {type(raised).__name__}",
        )
        self.assertIsInstance(
            raised.__cause__,
            sqlite3.Error,
            "StorageError 应包装底层 sqlite3 错误（__cause__），"
            f"实际 __cause__ 为 {raised.__cause__!r}",
        )

        self.assert_state_unchanged(state_before, "有效权限查询失败后")

    def test_several_valid_permissions_all_raise_storage_error(self):
        # 无论查询的权限名是否“看起来会命中”，只要查询触碰 permission 列
        # 就必然失败；每次失败都不得退化为 []。
        for permission in (
            PERMISSION_READ,
            PERMISSION_WRITE,
            PERMISSION_EXPORT,
            "accounts:delete",
        ):
            with self.subTest(permission=permission):
                with self.assertRaises(store.StorageError):
                    store.list_roles_for_permission(self.conn, permission)

    def test_repeated_failures_leave_schema_and_data_unchanged(self):
        # 连续多次失败后，原有表结构与 reader 记录仍保持原样：
        # 失败路径不补列、不清空数据，也不会“修复”表结构。
        state_before = self.stored_state()

        for permission in (PERMISSION_READ, PERMISSION_EXPORT):
            with self.assertRaises(store.StorageError):
                store.list_roles_for_permission(self.conn, permission)
            self.assert_state_unchanged(state_before, f"查询 {permission} 失败后")

        # 再查一次仍然失败：前两次失败没有改变任何状态。
        with self.assertRaises(store.StorageError):
            store.list_roles_for_permission(self.conn, PERMISSION_READ)
        self.assert_state_unchanged(state_before, "再次查询失败后")


if __name__ == "__main__":
    unittest.main()
