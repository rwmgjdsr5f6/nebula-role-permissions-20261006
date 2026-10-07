"""rbac.store.list_permissions_for_roles 多角色权限并集的回归测试。

不经过命令行子进程，直接传入角色列表调用存储层函数，
使用真实 SQLite 规则数据核对多角色去重合集。覆盖范围：

- 多角色并集与共享权限去重：reader 的 documents:read/documents:write
  与 editor 的 documents:read/reports:export 汇总后恰好为
  ["documents:read", "documents:write", "reports:export"]，
  共享的 documents:read 只出现一次，且不混入未请求角色 ghost 的权限；
- 角色顺序、重复角色或混入未知角色不影响结果；无成员绑定的 ghost
  单查仍返回 ["private:read"]；
- 空角色列表、全部未获授权的角色均返回 []；大小写敏感，Reader 单查
  返回 []；
- 权限名原样保留并按完整字符串的 Unicode 码点顺序升序返回：
  "A"、"a"、"中" 汇总为 ["A", "a", "中"]；
- 查询只读且结果稳定：重复调用结果相同，完整授权记录与调用方传入的
  角色列表均不变化；
- 存储失败与正常空结果的区别：现存规则表只有 role 列、缺少 permission
  列时，非空角色列表抛出 rbac.store.StorageError 而非返回 [] 或直接
  抛出 sqlite3 原始异常；同一连接传入空角色列表仍返回 []；两种调用
  均不补列、不改动预置数据。

只依赖 Python 3 标准库与 SQLite；每个用例使用独立临时数据库并释放连接，
不依赖任何已有规则文件。从项目根目录执行：

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
# - reader 持有 documents:read、documents:write；
# - editor 持有 documents:read（与 reader 共享，用于去重）、reports:export；
# - ghost 持有 private:read，但未关联任何固定成员，用于说明授权
#   不依赖成员配置。
SEED_RULES = (
    ("reader", PERMISSION_READ),
    ("reader", PERMISSION_WRITE),
    ("editor", PERMISSION_READ),
    ("editor", PERMISSION_EXPORT),
    ("ghost", PERMISSION_PRIVATE),
)

# reader 与 editor 的并集期望：共享的 documents:read 只出现一次，
# 按 Unicode 码点升序排列。
EXPECTED_READER_EDITOR = [
    PERMISSION_READ,
    PERMISSION_WRITE,
    PERMISSION_EXPORT,
]

# 独立样例角色：只持有 A、a、中 三条权限，不与预置角色混用。
# 权限名原样保留（含大小写与非 ASCII），按 Unicode 码点升序。
UNICODE_ROLE = "labels"
UNICODE_PERMISSIONS = ("中", "a", "A")
EXPECTED_UNICODE = ["A", "a", "中"]

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

        同一查询连续执行两次，结果必须一致且为全新列表对象；调用前后
        完整授权记录与调用方持有的角色列表均不得变化。
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
            f"{context}：重复调用结果应稳定，第一次 {first!r}，第二次 {second!r}",
        )
        self.assertIsNot(
            first,
            second,
            f"{context}：每次调用应返回独立的列表对象",
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

    # ---- 多角色并集与共享权限去重 ----------------------------------------

    def test_union_of_reader_and_editor_exact(self):
        # reader 与 editor 的并集恰好为三条权限；共享的 documents:read
        # 去重，且不得混入未请求角色 ghost 的 private:read。
        self.assert_permissions(
            ["reader", "editor"],
            EXPECTED_READER_EDITOR,
            "查询 [reader, editor]",
        )

    def test_role_order_duplicates_and_unknown_roles_ignored(self):
        # 交换角色顺序不影响并集。
        self.assert_permissions(
            ["editor", "reader"],
            EXPECTED_READER_EDITOR,
            "查询 [editor, reader]",
        )
        # 重复出现同一角色不改变并集，也不会产生重复权限。
        self.assert_permissions(
            ["reader", "editor", "reader", "editor"],
            EXPECTED_READER_EDITOR,
            "查询 [reader, editor, reader, editor]",
        )
        # 混入未获授权的未知角色不影响已知角色的并集。
        self.assert_permissions(
            ["reader", "nobody", "editor", "stranger"],
            EXPECTED_READER_EDITOR,
            "查询 [reader, nobody, editor, stranger]",
        )

    def test_ghost_without_member_binding_returns_its_permissions(self):
        # ghost 未关联任何固定成员，单查仍应返回其直接获授的权限。
        self.assert_permissions(
            ["ghost"],
            [PERMISSION_PRIVATE],
            "查询 [ghost]",
        )
        # ghost 与未知角色混查同样不串入其他角色权限。
        self.assert_permissions(
            ["nobody", "ghost"],
            [PERMISSION_PRIVATE],
            "查询 [nobody, ghost]",
        )

    # ---- 空结果与大小写敏感 ----------------------------------------------

    def test_empty_roles_returns_empty_list(self):
        # 空角色列表直接返回 []，不触碰规则表。
        self.assert_permissions([], [], "查询空角色列表")

    def test_all_unauthorized_roles_return_empty_list(self):
        # 全部角色均无任何授权时返回 []。
        self.assert_permissions(
            ["nobody", "stranger"],
            [],
            "查询 [nobody, stranger]",
        )

    def test_role_names_are_case_sensitive(self):
        # Reader 不等同于 reader：大写单查返回 []，而非 reader 的权限。
        self.assert_permissions(
            ["Reader"],
            [],
            "查询 [Reader]",
        )
        # 大小写混合的未知角色与真实角色混查时，只汇总真实角色部分。
        self.assert_permissions(
            ["Reader", "ghost"],
            [PERMISSION_PRIVATE],
            "查询 [Reader, ghost]",
        )

    # ---- 名称原样保留与 Unicode 码点排序 ---------------------------------

    def test_permission_names_preserved_and_sorted_by_codepoint(self):
        # 独立样例：给独立角色 labels 故意以乱序写入 "中"、"a"、"A"，
        # 查询结果必须按 Unicode 码点升序（A=U+0041 < a=U+0061 < 中=U+4E2D），
        # 名称原样保留、大小写不折叠，且不混入其他角色的权限。
        for permission in UNICODE_PERMISSIONS:
            self.assertTrue(
                store.grant_permission(self.conn, UNICODE_ROLE, permission),
                f"测试前置：预置规则 {UNICODE_ROLE}/{permission} 应实际新增",
            )
        self.assert_permissions(
            [UNICODE_ROLE],
            EXPECTED_UNICODE,
            "查询 [labels]（含 A/a/中 独立样例）",
        )
        # 与预置角色混查时，独立样例权限并入并集后同样按码点整体排序。
        self.assert_permissions(
            ["ghost", UNICODE_ROLE],
            ["A", "a", "private:read", "中"],
            "查询 [ghost, labels]",
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
        """直接读取 SQLite，返回 (建表语句, 全部行)。"""
        schema = self.conn.execute(
            "SELECT sql FROM sqlite_master WHERE name = 'role_permissions'"
        ).fetchone()[0]
        rows = sorted(self.conn.execute("SELECT role FROM role_permissions").fetchall())
        return schema, rows

    def test_missing_permission_column_raises_storage_error(self):
        state_before = self.stored_state()
        self.assertEqual(
            state_before,
            (_INCOMPATIBLE_SCHEMA, [("reader",)]),
            f"测试前置：表应只有 role 列并保存一行 reader，实际为 {state_before!r}",
        )

        # 非空角色列表必须触碰 permission 列：存储失败应抛出 StorageError，
        # 不得返回 [] 与正常空结果混淆，也不得让 sqlite3 原始异常外泄。
        with self.assertRaises(
            store.StorageError,
            msg="缺少 permission 列时非空角色列表应抛出 StorageError 而非返回 []",
        ) as ctx:
            store.list_permissions_for_roles(self.conn, ["reader"])
        self.assertNotIsInstance(
            ctx.exception,
            sqlite3.Error,
            "不应直接抛出 sqlite3 原始异常，应统一包装为 StorageError",
        )

        # 失败后不补列、不改动已有数据。
        self.assertEqual(
            self.stored_state(),
            state_before,
            f"失败后表结构与数据不应变化，调用前为 {state_before!r}，"
            f"之后为 {self.stored_state()!r}",
        )

    def test_empty_roles_on_incompatible_schema_returns_empty_list(self):
        state_before = self.stored_state()

        # 空角色列表不触碰规则表：同一连接上仍返回 []。
        self.assertEqual(
            store.list_permissions_for_roles(self.conn, []),
            [],
            "空角色列表应直接返回 []，即使规则表缺少 permission 列",
        )

        self.assertEqual(
            self.stored_state(),
            state_before,
            f"空角色列表查询不应改动表结构与数据，调用前为 {state_before!r}，"
            f"之后为 {self.stored_state()!r}",
        )


if __name__ == "__main__":
    unittest.main()
