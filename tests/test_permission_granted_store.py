"""rbac.store.permission_granted 直接角色匹配的回归测试。

不经过命令行子进程，直接传入角色列表与权限名调用存储层函数，
使用真实 SQLite 规则数据核对布尔结果。覆盖范围：

- 任一角色命中即允许：["reader", "editor"] 查询 documents:write 时
  即使只有第二个角色获授也返回 True；交换角色顺序、重复角色结果不变；
- 授权不串角色、不串权限：reader 的 documents:write、editor 的
  documents:read、从未获授任何权限的角色、空角色列表均返回 False；
- 大小写敏感的完整字符串匹配：Reader 不等于 reader，
  Documents:read 不等于 documents:read；
- "%" 为普通字符：documents:% 不匹配已有的 documents:read，
  只有显式保存 documents:% 后相同查询才返回 True；
- 查询只读且结果稳定：每次调用前后角色输入与完整授权记录一致，
  重复调用结果相同；
- 存储失败与正常拒绝的区别：现存规则表只有 role 列、缺少 permission
  列时，非空角色列表抛出 rbac.store.StorageError 而非返回 False；
  同一连接传入空角色列表仍返回 False；失败后不补列、不改动已有数据。

只依赖 Python 3 标准库与 SQLite；每个用例使用独立临时数据库并释放连接。
从项目根目录执行：

    python -m unittest discover -s tests
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

# 固定样例规则库：reader 的 documents:read、editor 的 documents:write、
# ghost 的 documents:read。ghost 未关联任何固定成员，用于说明授权
# 不依赖成员配置。
SEED_RULES = (
    ("reader", PERMISSION_READ),
    ("editor", PERMISSION_WRITE),
    ("ghost", PERMISSION_READ),
)

# 不兼容的表结构：只有 role 列，缺少 permission 列。
_INCOMPATIBLE_SCHEMA = "CREATE TABLE role_permissions (role TEXT)"


class PermissionGrantedTests(unittest.TestCase):
    """在固定样例规则库上核对任一角色命中语义。"""

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

    def assert_granted(self, roles, permission, expected, context):
        """核对查询结果，并验证调用只读、结果稳定、不改动角色输入。

        同一查询连续执行两次，结果必须一致；调用前后完整授权记录与
        调用方持有的角色列表均不得变化。
        """
        roles_before = list(roles)
        rules_before = self.stored_rules()

        first = store.permission_granted(self.conn, roles, permission)
        second = store.permission_granted(self.conn, roles, permission)

        self.assertIs(
            first,
            expected,
            f"{context}：期望 {expected!r}，实际为 {first!r}",
        )
        self.assertEqual(
            second,
            first,
            f"{context}：重复调用结果应稳定，第一次 {first!r}，第二次 {second!r}",
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

    # ---- 任一角色命中即允许 ----------------------------------------------

    def test_any_single_role_hit_allows(self):
        # 样例中只有第二个角色 editor 获授 documents:write，
        # 任一角色命中即应允许。
        self.assert_granted(
            ["reader", "editor"],
            PERMISSION_WRITE,
            True,
            "查询 [reader, editor]/documents:write",
        )

    def test_role_order_and_duplicates_do_not_change_result(self):
        # 交换角色顺序后仍只有 editor 命中，结果不变。
        self.assert_granted(
            ["editor", "reader"],
            PERMISSION_WRITE,
            True,
            "查询 [editor, reader]/documents:write",
        )
        # 重复出现同一角色不改变命中语义。
        self.assert_granted(
            ["reader", "editor", "editor"],
            PERMISSION_WRITE,
            True,
            "查询 [reader, editor, editor]/documents:write",
        )
        # 未关联成员的 ghost 持有 documents:read，同样按直接角色命中。
        self.assert_granted(
            ["nobody", "ghost"],
            PERMISSION_READ,
            True,
            "查询 [nobody, ghost]/documents:read",
        )

    # ---- 授权不串角色、不串权限 ------------------------------------------

    def test_no_role_hit_denies(self):
        # reader 只获授 documents:read，不含 documents:write。
        self.assert_granted(
            ["reader"],
            PERMISSION_WRITE,
            False,
            "查询 [reader]/documents:write",
        )
        # editor 只获授 documents:write，不含 documents:read。
        self.assert_granted(
            ["editor"],
            PERMISSION_READ,
            False,
            "查询 [editor]/documents:read",
        )
        # 从未获授任何权限的角色。
        self.assert_granted(
            ["nobody"],
            PERMISSION_READ,
            False,
            "查询 [nobody]/documents:read",
        )
        # 空角色列表直接拒绝。
        self.assert_granted(
            [],
            PERMISSION_READ,
            False,
            "查询空角色列表/documents:read",
        )

    # ---- 精确匹配 ---------------------------------------------------------

    def test_matching_is_case_sensitive(self):
        # Reader 不等同于 reader。
        self.assert_granted(
            ["Reader"],
            PERMISSION_READ,
            False,
            "查询 [Reader]/documents:read",
        )
        # Documents:read 不等同于 documents:read。
        self.assert_granted(
            ["reader"],
            "Documents:read",
            False,
            "查询 [reader]/Documents:read",
        )

    def test_percent_sign_matches_literally(self):
        # "%" 是普通字符而非通配符：documents:% 不得匹配已有的
        # documents:read。
        self.assert_granted(
            ["reader"],
            "documents:%",
            False,
            "查询 [reader]/documents:%（未保存该权限）",
        )

        # 显式为 reader 保存 documents:% 后，相同查询才返回 True。
        self.assertTrue(
            store.grant_permission(self.conn, "reader", "documents:%"),
            "测试前置：保存 reader/documents:% 应实际新增",
        )
        self.assert_granted(
            ["reader"],
            "documents:%",
            True,
            "查询 [reader]/documents:%（已保存该权限）",
        )
        # 新增 documents:% 不影响原有 documents:read 的命中。
        self.assert_granted(
            ["reader"],
            PERMISSION_READ,
            True,
            "保存 documents:% 后查询 [reader]/documents:read",
        )


class PermissionGrantedIncompatibleSchemaTests(unittest.TestCase):
    """缺少 permission 列的现存规则表：存储失败不得退化为正常拒绝。"""

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
        # 不得返回 False 与正常拒绝混淆。
        with self.assertRaises(
            store.StorageError,
            msg="缺少 permission 列时非空角色列表应抛出 StorageError 而非返回 False",
        ):
            store.permission_granted(self.conn, ["reader"], PERMISSION_READ)

        # 失败后不补列、不改动已有数据。
        self.assertEqual(
            self.stored_state(),
            state_before,
            f"失败后表结构与数据不应变化，调用前为 {state_before!r}",
        )

    def test_empty_roles_on_incompatible_schema_returns_false(self):
        state_before = self.stored_state()

        # 空角色列表不触碰规则表：同一连接上仍返回 False。
        self.assertIs(
            store.permission_granted(self.conn, [], PERMISSION_READ),
            False,
            "空角色列表应直接返回 False，即使规则表缺少 permission 列",
        )

        self.assertEqual(
            self.stored_state(),
            state_before,
            f"空角色列表查询不应改动表结构与数据，调用前为 {state_before!r}",
        )


if __name__ == "__main__":
    unittest.main()
