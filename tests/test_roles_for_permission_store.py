"""rbac.store.list_roles_for_permission 按权限反查角色的回归测试。

list-permission-roles 反查某权限的直接角色时，用该函数对规则库做只读
查询。本测试不经过命令行子进程，直接传入权限名调用存储层函数，使用真实
SQLite 数据核对反查语义。覆盖范围：

- 固定样例反查：reader 获授 documents:read、documents:write，editor 获授
  documents:read，ghost 仅获授 reports:export。反查 documents:read 恰好
  返回 ["editor", "reader"]，反查 documents:write 恰好返回 ["reader"]，
  查询从未授予的权限返回 []；editor 未绑定固定成员仍进入结果，ghost 的
  reports:export 不得混入其他权限的结果；
- 精确匹配：权限名按传入原值匹配，不去除首尾空白、不统一大小写——给
  documents:read 添加首尾空白或改变大小写均返回 []；"*"、"%"、"_" 按
  普通字符处理，仅匹配完全相同的完整名称；
- 去重、Unicode 码点排序与原名保留：独立规则表只含 role、permission 两个
  文本列且允许重复行，A、a、中 三个角色保存同一权限并重复一行，结果仍为
  ["A", "a", "中"]；
- 查询只读且结果稳定：重复调用结果一致，调用前后完整授权记录不变化；
- 区分空结果与存储失败：现存 role_permissions 表只有 role 列、缺少
  permission 列并保存一行 reader 时，传入有效权限查询抛出
  rbac.store.StorageError，不能返回 []，也不得直接抛出 sqlite3 原始异常；
  失败后原有表结构与记录保持不变。

断言只针对固定预期结果与真实数据，不绑定特定 SQL 文本或内部调用次数。
只依赖 Python 3 标准库与 SQLite；每个用例使用独立临时数据库文件，连接在
用例结束时关闭释放，不依赖任何已有规则文件或用例顺序。从项目根目录执行：

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
# editor 持有 documents:read（未绑定任何固定成员）；
# ghost 仅持有 reports:export。
SEED_RULES = (
    ("reader", PERMISSION_READ),
    ("reader", PERMISSION_WRITE),
    ("editor", PERMISSION_READ),
    ("ghost", PERMISSION_EXPORT),
)

# 不兼容的表结构：只有 role 列，缺少 permission 列。
_INCOMPATIBLE_SCHEMA = "CREATE TABLE role_permissions (role TEXT)"

# 宽松表结构：只有 role、permission 两个文本列，无主键，允许重复行。
_LOOSE_SCHEMA = (
    "CREATE TABLE role_permissions (role TEXT, permission TEXT)"
)


class RolesForPermissionTests(unittest.TestCase):
    """在固定样例规则库上核对按权限反查角色的语义。"""

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
        """核对反查结果，并验证调用只读、结果稳定。

        同一查询连续执行两次，结果必须一致；调用前后完整授权记录不得变化。
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

    # ---- 固定样例反查 ----------------------------------------------------

    def test_read_permission_returns_editor_and_reader(self):
        # documents:read 授予了 reader 与 editor；editor 未绑定固定成员，
        # 但直接角色授权不依赖成员配置，仍应进入结果。
        result = store.list_roles_for_permission(self.conn, PERMISSION_READ)
        self.assertEqual(
            result,
            ["editor", "reader"],
            f"反查 {PERMISSION_READ} 与预期不符，实际为 {result!r}",
        )
        # 钉死“恰好”：不多一项（无 ghost），不少一项，也无重复。
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
            f"ghost 未获授 {PERMISSION_READ}，不得混入结果，实际为 {result!r}",
        )
        # 按 Unicode 码点升序：editor < reader。
        self.assertEqual(
            result,
            sorted(result),
            f"角色应按 Unicode 码点升序排列，实际为 {result!r}",
        )

    def test_write_permission_returns_only_reader(self):
        self.assert_roles(
            PERMISSION_WRITE,
            ["reader"],
            f"反查 {PERMISSION_WRITE}",
        )

    def test_export_permission_returns_only_ghost(self):
        # ghost 的 reports:export 只在自己权限的反查中出现。
        self.assert_roles(
            PERMISSION_EXPORT,
            ["ghost"],
            f"反查 {PERMISSION_EXPORT}",
        )

    def test_ungranted_permission_returns_empty_list(self):
        self.assert_roles(
            "documents:delete",
            [],
            "反查从未授予的 documents:delete",
        )
        self.assert_roles(
            "",
            [],
            "反查空权限名",
        )

    # ---- 精确匹配：不裁剪、不统一大小写、通配符按普通字符 -----------------

    def test_permission_matching_is_exact_and_case_sensitive(self):
        # 函数不替调用方去除首尾空白：带空白的名称匹配不到任何规则。
        self.assert_roles(
            " " + PERMISSION_READ,
            [],
            "反查带前导空白的权限名",
        )
        self.assert_roles(
            PERMISSION_READ + " ",
            [],
            "反查带尾随空白的权限名",
        )
        self.assert_roles(
            " " + PERMISSION_READ + " ",
            [],
            "反查首尾均带空白的权限名",
        )
        # 大小写不同的名称是另一个权限。
        self.assert_roles(
            "Documents:Read",
            [],
            "反查改变大小写的权限名",
        )
        self.assert_roles(
            PERMISSION_READ.upper(),
            [],
            "反查全大写的权限名",
        )

    def test_wildcard_characters_are_ordinary_characters(self):
        # "*"、"%"、"_" 按普通字符处理，仅匹配完全相同的完整名称。
        self.assert_roles(
            "documents:*",
            [],
            "反查含 * 的权限名",
        )
        self.assert_roles(
            "documents:%",
            [],
            "反查含 % 的权限名",
        )
        self.assert_roles(
            "documents:rea_",
            [],
            "反查含 _ 的权限名",
        )
        self.assert_roles(
            "%",
            [],
            "反查仅含 % 的权限名",
        )
        # 库中真实保存含通配符的权限名时，按完整名称精确命中。
        self.assertTrue(
            store.grant_permission(self.conn, "ops", "reports:%"),
            "测试前置：预置规则 ops/reports:% 应实际新增",
        )
        self.assert_roles(
            "reports:%",
            ["ops"],
            "反查库中真实保存的含 % 权限名",
        )
        # 该精确授权不影响其他权限的反查结果。
        self.assert_roles(
            PERMISSION_EXPORT,
            ["ghost"],
            "新增 ops/reports:% 后反查 reports:export",
        )

    # ---- 去重、码点排序与原名保留 ----------------------------------------

    def test_dedup_unicode_sort_and_name_preservation_on_loose_table(self):
        # 独立规则表：只含 role、permission 两个文本列，无主键，允许重复行。
        loose_db = os.path.join(self._tmpdir.name, "loose_rules.db")
        with sqlite3.connect(loose_db) as setup_conn:
            setup_conn.execute(_LOOSE_SCHEMA)
            # 故意按与码点顺序不同的次序写入，并重复一行。
            setup_conn.executemany(
                "INSERT INTO role_permissions (role, permission) VALUES (?, ?)",
                [
                    ("中", "perm"),
                    ("a", "perm"),
                    ("A", "perm"),
                    ("A", "perm"),
                ],
            )
        conn = store.connect(loose_db)
        self.addCleanup(conn.close)

        rules_before = sorted(
            conn.execute(
                "SELECT role, permission FROM role_permissions"
            ).fetchall()
        )
        self.assertEqual(
            rules_before,
            [("A", "perm"), ("A", "perm"), ("a", "perm"), ("中", "perm")],
            f"测试前置：宽松表应保存 4 行（含重复行），实际为 {rules_before!r}",
        )

        result = store.list_roles_for_permission(conn, "perm")
        # 重复行去重；角色名原样保留（大小写、中文字符不转换）；
        # 按 Unicode 码点升序：A(0x41) < a(0x61) < 中(0x4E2D)。
        self.assertEqual(
            result,
            ["A", "a", "中"],
            f"角色名应去重、原样保留并按 Unicode 码点升序返回，实际为 {result!r}",
        )
        # 重复查询结果一致。
        self.assertEqual(
            store.list_roles_for_permission(conn, "perm"),
            result,
            "宽松表重复查询结果应一致",
        )
        # 授权记录（含重复行）未被查询改写。
        self.assertEqual(
            sorted(
                conn.execute(
                    "SELECT role, permission FROM role_permissions"
                ).fetchall()
            ),
            rules_before,
            "宽松表查询不应改动授权记录（含重复行）",
        )

    def test_query_does_not_modify_seed_rules(self):
        # 对主样例库执行各类查询后，完整授权记录应与预置完全一致。
        for permission in (
            PERMISSION_READ,
            PERMISSION_WRITE,
            PERMISSION_EXPORT,
            "documents:delete",
            " " + PERMISSION_READ,
            PERMISSION_READ.upper(),
            "documents:*",
            "%",
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

        # 查询必须触碰 permission 列：缺列导致存储失败，应抛出
        # rbac.store.StorageError，而非返回 [] 把失败伪装成空结果。
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

        self.assert_state_unchanged(state_before, "存储失败后")

    def test_several_permission_inputs_all_raise_storage_error(self):
        # 无论权限名是否在库中出现过，只要查询 permission 列就必然失败；
        # 未授予的权限名同样失败，不能因“正常空结果”而返回 []。
        for permission in (
            PERMISSION_READ,
            PERMISSION_WRITE,
            "documents:delete",
            "",
        ):
            with self.subTest(permission=permission):
                with self.assertRaises(store.StorageError):
                    store.list_roles_for_permission(self.conn, permission)

    def test_repeated_failures_leave_state_unchanged(self):
        # 同一连接上连续触发失败：每次都不补列、不改预置数据，
        # 且后续失败不被前一次失败污染。
        state_before = self.stored_state()

        with self.assertRaises(store.StorageError):
            store.list_roles_for_permission(self.conn, PERMISSION_READ)
        self.assert_state_unchanged(state_before, "第一次存储失败后")

        with self.assertRaises(store.StorageError):
            store.list_roles_for_permission(self.conn, PERMISSION_WRITE)
        self.assert_state_unchanged(state_before, "第二次存储失败后")


if __name__ == "__main__":
    unittest.main()
