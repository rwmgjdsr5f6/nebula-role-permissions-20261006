"""rbac.store.list_permissions_for_roles 多角色权限并集的回归测试。

list-member-permissions 汇总成员权限时，用该函数对成员的全部直接角色
求权限并集。本测试不经过命令行子进程，直接传入角色列表调用存储层函数，
使用真实 SQLite 数据核对并集语义。覆盖范围：

- 多角色并集与共享权限去重：reader 获授 documents:read、documents:write，
  editor 获授 documents:read、reports:export，查询 ["reader", "editor"]
  恰好返回 ["documents:read", "documents:write", "reports:export"]，
  共享的 documents:read 只出现一次，且不混入其他角色（ghost）的权限；
- 角色顺序、重复角色、混入未知角色均不影响结果；未绑定任何固定成员的
  ghost 单查返回 ["private:read"]；
- 空角色列表、全部未获授权的角色均返回 []；大小写敏感：Reader 不是 reader，
  单查 Reader 返回 []；
- 名称原样保留并按 Unicode 码点升序：独立样例中权限 "A"、"a"、"中"
  返回 ["A", "a", "中"]；
- 查询只读且结果稳定：重复调用结果一致，调用前后完整授权记录与调用方
  持有的角色列表均不变化；
- 区分空结果与存储失败：现存 role_permissions 表只有 role 列、缺少
  permission 列并保存一行 reader 时，非空角色列表查询抛出
  rbac.store.StorageError，不能返回 []，也不得直接抛出 sqlite3 原始异常；
  同一连接传入空角色列表仍返回 []；两种调用均不补列、不改预置数据。

只依赖 Python 3 标准库与 SQLite；每个用例使用独立临时数据库文件，
连接在用例结束时关闭释放，不依赖任何已有规则文件。从项目根目录执行：

    python -m unittest discover -s tests -p test_permissions_for_roles_store.py
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
PERMISSION_PRIVATE = "private:read"

# 固定样例规则库：
# reader 持有 documents:read、documents:write；
# editor 持有 documents:read、reports:export（与 reader 共享 read）；
# ghost 持有 private:read，且 ghost 未关联任何固定成员。
SEED_RULES = (
    ("reader", PERMISSION_READ),
    ("reader", PERMISSION_WRITE),
    ("editor", PERMISSION_READ),
    ("editor", PERMISSION_EXPORT),
    ("ghost", PERMISSION_PRIVATE),
)

# 不兼容的表结构：只有 role 列，缺少 permission 列。
_INCOMPATIBLE_SCHEMA = "CREATE TABLE role_permissions (role TEXT)"


class PermissionsForRolesTests(unittest.TestCase):
    """在固定样例规则库上核对多角色权限并集语义。"""

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

    def assert_permissions(self, roles, expected, context):
        """核对并集结果，并验证调用只读、结果稳定、不改动角色输入。

        同一查询连续执行两次，结果必须一致；调用前后完整授权记录与
        调用方持有的角色列表均不得变化。
        """
        roles_before = list(roles)
        rules_before = self.stored_rules()

        first = store.list_permissions_for_roles(self.conn, roles)
        second = store.list_permissions_for_roles(self.conn, roles)

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
            roles,
            roles_before,
            f"{context}：调用不应改动角色输入，之前 {roles_before!r}，"
            f"之后 {roles!r}",
        )
        self.assertEqual(
            self.stored_rules(),
            rules_before,
            f"{context}：查询不应改动授权记录，之前 {rules_before!r}，"
            f"之后 {self.stored_rules()!r}",
        )

    # ---- 多角色并集与去重 -----------------------------------------------

    def test_reader_editor_union_is_deduped_and_exact(self):
        # reader 与 editor 共享 documents:read，并集只出现一次；
        # 结果恰好为三个权限，ghost 的 private:read 不得混入。
        result = store.list_permissions_for_roles(
            self.conn, ["reader", "editor"]
        )
        self.assertEqual(
            result,
            [PERMISSION_READ, PERMISSION_WRITE, PERMISSION_EXPORT],
            f"[reader, editor] 的权限并集与预期不符，实际为 {result!r}",
        )
        # 钉死“恰好”：不多一项（无 ghost 权限），不少一项，也无重复。
        self.assertEqual(
            len(result),
            3,
            f"并集应恰好含 3 个权限，实际为 {result!r}",
        )
        self.assertEqual(
            len(result),
            len(set(result)),
            f"并集中不得有重复权限，实际为 {result!r}",
        )
        self.assertNotIn(
            PERMISSION_PRIVATE,
            result,
            f"未查询 ghost 时不得混入其权限 private:read，实际为 {result!r}",
        )
        # 按 Unicode 码点升序：documents:read < documents:write < reports:export。
        self.assertEqual(
            result,
            sorted(result),
            f"权限应按 Unicode 码点升序排列，实际为 {result!r}",
        )

    def test_role_order_duplicates_and_unknown_roles_do_not_change_result(self):
        expected = [PERMISSION_READ, PERMISSION_WRITE, PERMISSION_EXPORT]
        # 交换角色顺序。
        self.assert_permissions(
            ["editor", "reader"],
            expected,
            "查询 [editor, reader]",
        )
        # 重复出现同一角色。
        self.assert_permissions(
            ["reader", "editor", "reader", "editor"],
            expected,
            "查询含重复角色的 [reader, editor, reader, editor]",
        )
        # 混入从未获授任何权限的未知角色。
        self.assert_permissions(
            ["reader", "stranger", "editor", "nobody"],
            expected,
            "查询混入未知角色的 [reader, stranger, editor, nobody]",
        )

    def test_ghost_without_member_binding_returns_its_permission(self):
        # ghost 未关联任何固定成员，但直接角色授权不依赖成员配置。
        self.assert_permissions(
            ["ghost"],
            [PERMISSION_PRIVATE],
            "单查未绑定成员的 ghost",
        )
        # ghost 与未知角色一起查询时仍是其自身权限。
        self.assert_permissions(
            ["stranger", "ghost"],
            [PERMISSION_PRIVATE],
            "查询 [stranger, ghost]",
        )

    def test_single_role_returns_only_its_own_permissions(self):
        self.assert_permissions(
            ["reader"],
            [PERMISSION_READ, PERMISSION_WRITE],
            "单查 reader",
        )
        self.assert_permissions(
            ["editor"],
            [PERMISSION_READ, PERMISSION_EXPORT],
            "单查 editor",
        )

    # ---- 空结果 ----------------------------------------------------------

    def test_empty_roles_returns_empty_list(self):
        self.assert_permissions([], [], "查询空角色列表")

    def test_all_unauthorized_roles_return_empty_list(self):
        # 全部角色都从未获授任何权限。
        self.assert_permissions(
            ["stranger", "nobody"],
            [],
            "查询全部未获授权的角色",
        )
        # 未获授权角色与空结果重复、混排也仍为空。
        self.assert_permissions(
            ["nobody", "nobody", "stranger"],
            [],
            "查询重复的未授权角色",
        )

    def test_role_matching_is_case_sensitive(self):
        # Reader 不等同于 reader：大小写不同的角色名没有任何授权。
        self.assert_permissions(
            ["Reader"],
            [],
            "单查 Reader（大写）",
        )
        # 与 reader 混查时，Reader 不贡献权限也不影响 reader 的结果。
        self.assert_permissions(
            ["Reader", "reader"],
            [PERMISSION_READ, PERMISSION_WRITE],
            "查询 [Reader, reader]",
        )

    # ---- 名称原样保留与码点排序 ------------------------------------------

    def test_permission_names_preserved_and_sorted_by_unicode_codepoint(self):
        # 独立样例：同一角色获授名称大小写与非 ASCII 不同的三个权限。
        unicode_db = os.path.join(self._tmpdir.name, "unicode_rules.db")
        conn = store.connect(unicode_db)
        self.addCleanup(conn.close)
        # 故意按与码点顺序不同的次序写入。
        for permission in ("中", "a", "A"):
            self.assertTrue(
                store.grant_permission(conn, "sample", permission),
                f"测试前置：预置规则 sample/{permission} 应实际新增",
            )

        result = store.list_permissions_for_roles(conn, ["sample"])
        # 名称原样保留（大小写、中文字符不转换），按 Unicode 码点升序：
        # A(0x41) < a(0x61) < 中(0x4E2D)。
        self.assertEqual(
            result,
            ["A", "a", "中"],
            f"权限名应原样保留并按 Unicode 码点升序返回，实际为 {result!r}",
        )
        # 重复查询结果一致。
        self.assertEqual(
            store.list_permissions_for_roles(conn, ["sample"]),
            result,
            "独立样例重复查询结果应一致",
        )
        # 授权记录仍是写入的三条，未被查询改写。
        self.assertEqual(
            sorted(
                conn.execute(
                    "SELECT role, permission FROM role_permissions"
                ).fetchall()
            ),
            [("sample", "A"), ("sample", "a"), ("sample", "中")],
            f"独立样例授权记录与预置不符，实际为 "
            f"{sorted(conn.execute('SELECT role, permission FROM role_permissions').fetchall())!r}",
        )

    def test_query_does_not_modify_seed_rules(self):
        # 对主样例库执行各类查询后，完整授权记录应与预置完全一致。
        for roles in (
            [],
            ["reader", "editor"],
            ["editor", "reader", "reader"],
            ["ghost"],
            ["stranger"],
            ["Reader"],
            ["reader", "stranger", "ghost"],
        ):
            with self.subTest(roles=roles):
                store.list_permissions_for_roles(self.conn, roles)

        self.assertEqual(
            self.stored_rules(),
            sorted(SEED_RULES),
            f"全部查询后授权记录应与预置一致，实际为 {self.stored_rules()!r}",
        )


class PermissionsForRolesIncompatibleSchemaTests(unittest.TestCase):
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

    def test_non_empty_roles_raise_storage_error(self):
        state_before = self.stored_state()
        self.assertEqual(
            state_before,
            (_INCOMPATIBLE_SCHEMA, [(0, "role", "TEXT", 0, None, 0)], [("reader",)]),
            f"测试前置：表应只有 role 列并保存一行 reader，实际为 {state_before!r}",
        )

        # 非空角色列表必须触碰 permission 列：缺列导致存储失败，
        # 应抛出 rbac.store.StorageError，而非返回 [] 把失败伪装成空结果。
        with self.assertRaises(
            store.StorageError,
            msg="缺少 permission 列时非空角色列表查询应抛出 StorageError",
        ) as assertion_context:
            store.list_permissions_for_roles(self.conn, ["reader"])

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

        self.assert_state_unchanged(state_before, "非空角色列表查询失败后")

    def test_several_non_empty_role_inputs_all_raise_storage_error(self):
        # 表中的 reader 行与不在表中的角色没有区别：只要查询 permission 列
        # 就必然失败；重复角色同样失败。
        for roles in (
            ["ghost"],
            ["reader", "editor"],
            ["stranger"],
            ["reader", "reader"],
        ):
            with self.subTest(roles=roles):
                with self.assertRaises(store.StorageError):
                    store.list_permissions_for_roles(self.conn, roles)

    def test_empty_roles_on_incompatible_schema_returns_empty_list(self):
        state_before = self.stored_state()

        # 空角色列表不触碰规则表：同一连接上仍返回 []，缺列不影响此结果。
        result = store.list_permissions_for_roles(self.conn, [])
        self.assertEqual(
            result,
            [],
            f"空角色列表应返回 []，即使规则表缺少 permission 列，"
            f"实际为 {result!r}",
        )

        self.assert_state_unchanged(state_before, "空角色列表查询后")

    def test_failure_and_empty_result_both_leave_state_unchanged(self):
        # 在同一连接上先触发存储失败、再走空列表的正常空结果：
        # 两种路径都不得补列或改动预置数据，且空结果路径不被前一次失败污染。
        state_before = self.stored_state()

        with self.assertRaises(store.StorageError):
            store.list_permissions_for_roles(self.conn, ["reader"])
        self.assert_state_unchanged(state_before, "存储失败后")

        self.assertEqual(
            store.list_permissions_for_roles(self.conn, []),
            [],
            "存储失败后，空角色列表查询仍应返回 []",
        )
        self.assert_state_unchanged(state_before, "随后空角色列表查询后")

        # 再次以非空角色查询仍应失败：空列表的成功调用不修复任何东西。
        with self.assertRaises(store.StorageError):
            store.list_permissions_for_roles(self.conn, ["reader"])
        self.assert_state_unchanged(state_before, "再次存储失败后")


if __name__ == "__main__":
    unittest.main()
