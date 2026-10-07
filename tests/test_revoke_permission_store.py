"""rbac.store.revoke_permission 直接撤销授权的存储层回归测试。

不经过命令行子进程，直接调用 rbac.store.revoke_permission，在独立临时
SQLite 规则库上核对返回值、真实删除与持久化结果的一致性。覆盖范围：

- 真实删除：预置 reader/documents:read、reader/documents:write、
  editor/documents:read 三条规则，在同一连接上撤销第一条返回布尔值
  True，库中恰好只剩另外两条——核对完整规则集合，漏删或误删其他
  授权都会被发现；
- 幂等撤销：重复撤销同一组合返回布尔值 False，记录不再变化；
- 未授权组合：撤销从未授权的 ghost/documents:read 返回布尔值 False，
  既有规则不受影响；
- 持久化核对：关闭连接并重新打开文件后，删除结果仍然有效，剩余规则
  与删除后完全一致；
- 结构不兼容：role_permissions 表只有 role 列时，撤销抛出
  rbac.store.StorageError——不得返回 False，也不得让 sqlite3 原生
  异常逸出；调用前后及重新打开后表结构与原有记录均不改变。

名称规整（首尾空白裁剪与 invalid_name 判定）由命令行入口负责，本测试
只传入已规整的合成名称。只依赖 Python 3 标准库与 SQLite；每个用例独立
准备数据、关闭连接并清理临时文件，不接触已有规则库。从项目根目录执行：

    python -m unittest discover -s tests -p test_revoke_permission_store.py
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

# 标准表结构：与 store._SCHEMA 相同的复合主键授权表。
_STANDARD_SCHEMA = (
    "CREATE TABLE role_permissions ("
    "role TEXT NOT NULL, permission TEXT NOT NULL, "
    "PRIMARY KEY (role, permission))"
)

# 预置的三条规则及其（角色, 权限）排序后的完整列表。
_SEED_RULES = [
    ("reader", PERMISSION_READ),
    ("reader", PERMISSION_WRITE),
    ("editor", PERMISSION_READ),
]
# 撤销 (reader, documents:read) 后应恰好剩余的两条规则（排序后）。
_RULES_AFTER_REVOKE = sorted(
    [("editor", PERMISSION_READ), ("reader", PERMISSION_WRITE)]
)

# 不兼容的表结构：只有 role 列，缺少 permission 列。
_INCOMPATIBLE_SCHEMA = "CREATE TABLE role_permissions (role TEXT)"


class RevokePermissionStoreTests(unittest.TestCase):
    """同一连接上撤销授权的返回值与落库、持久化一致性。"""

    def setUp(self):
        # 每个用例独立的临时目录，TemporaryDirectory.cleanup 负责清理。
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.db_path = os.path.join(self._tmpdir.name, "rules.db")
        # 准备测试输入：标准授权表，预置 reader 两条、editor 一条规则。
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(_STANDARD_SCHEMA)
            conn.executemany(
                "INSERT INTO role_permissions (role, permission) "
                "VALUES (?, ?)",
                _SEED_RULES,
            )
        # 通过现有连接入口打开：CREATE TABLE IF NOT EXISTS 对已有表为
        # 空操作，不改变既有表结构与数据。
        self.conn = store.connect(self.db_path)
        self.addCleanup(self.conn.close)

    # ---- 辅助方法 -------------------------------------------------------

    def stored_rules(self, conn=None):
        """直接读取 SQLite，返回排序后的全部 (role, permission) 规则。"""
        conn = self.conn if conn is None else conn
        return sorted(
            conn.execute(
                "SELECT role, permission FROM role_permissions"
            ).fetchall()
        )

    # ---- 真实删除 --------------------------------------------------------

    def test_revoke_existing_rule_returns_true_and_removes_only_that_rule(self):
        # 测试前置：恰有三条预置规则。
        self.assertEqual(
            self.stored_rules(),
            sorted(_SEED_RULES),
            f"测试前置：应预置三条规则 {sorted(_SEED_RULES)!r}，"
            f"实际为 {self.stored_rules()!r}",
        )

        revoked = store.revoke_permission(self.conn, "reader", PERMISSION_READ)
        self.assertIs(
            revoked,
            True,
            f"撤销已存在的 reader/{PERMISSION_READ} 应返回布尔值 True，"
            f"实际为 {revoked!r}",
        )
        # 核对完整规则集合：只删目标一条，其余两条原样保留——
        # 漏删目标或误删其他授权都会使集合不等。
        self.assertEqual(
            self.stored_rules(),
            _RULES_AFTER_REVOKE,
            f"撤销后应恰好剩余 {_RULES_AFTER_REVOKE!r}，"
            f"实际为 {self.stored_rules()!r}",
        )

    def test_revoke_same_rule_twice_returns_false_and_keeps_state(self):
        first = store.revoke_permission(self.conn, "reader", PERMISSION_READ)
        self.assertIs(first, True, "首次撤销应返回布尔值 True")
        state_after_first = self.stored_rules()

        second = store.revoke_permission(self.conn, "reader", PERMISSION_READ)
        self.assertIs(
            second,
            False,
            f"重复撤销同一组合应返回布尔值 False，实际为 {second!r}",
        )
        self.assertEqual(
            self.stored_rules(),
            state_after_first,
            f"重复撤销不应改变记录，之前 {state_after_first!r}，"
            f"之后 {self.stored_rules()!r}",
        )

    def test_revoke_never_granted_role_returns_false_and_keeps_state(self):
        state_before = self.stored_rules()

        revoked = store.revoke_permission(self.conn, "ghost", PERMISSION_READ)
        self.assertIs(
            revoked,
            False,
            f"撤销从未授权的 ghost/{PERMISSION_READ} 应返回布尔值 False，"
            f"实际为 {revoked!r}",
        )
        self.assertEqual(
            self.stored_rules(),
            state_before,
            f"撤销未授权组合不应改变任何记录，之前 {state_before!r}，"
            f"之后 {self.stored_rules()!r}",
        )

    # ---- 持久化核对 ------------------------------------------------------

    def test_revoke_persists_after_reopen(self):
        revoked = store.revoke_permission(self.conn, "reader", PERMISSION_READ)
        self.assertIs(revoked, True, "首次撤销应返回布尔值 True")

        # 关闭并重新打开文件：通过新连接核对删除结果仍然有效。
        self.conn.close()
        reopened = store.connect(self.db_path)
        try:
            rows = self.stored_rules(reopened)
        finally:
            reopened.close()
        self.assertEqual(
            rows,
            _RULES_AFTER_REVOKE,
            f"重新打开后规则应恰好为 {_RULES_AFTER_REVOKE!r}，"
            f"实际为 {rows!r}",
        )
        self.assertNotIn(
            ("reader", PERMISSION_READ),
            rows,
            f"已撤销的 reader/{PERMISSION_READ} 不应在重新打开后重现，"
            f"实际为 {rows!r}",
        )


class RevokePermissionIncompatibleSchemaTests(unittest.TestCase):
    """缺少 permission 列时撤销必须抛出 StorageError 且不改数据。"""

    def setUp(self):
        # 每个用例独立的临时目录，TemporaryDirectory.cleanup 负责清理。
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.db_path = os.path.join(self._tmpdir.name, "rules.db")
        # 准备测试输入：表只有 role 列并保存一行 reader，缺少
        # permission 列；数据库可正常打开（CREATE TABLE IF NOT EXISTS
        # 对已有表为空操作）。
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(_INCOMPATIBLE_SCHEMA)
            conn.execute(
                "INSERT INTO role_permissions (role) VALUES ('reader')"
            )
        self.conn = store.connect(self.db_path)
        self.addCleanup(self.conn.close)

    # ---- 辅助方法 -------------------------------------------------------

    def stored_state(self, conn=None):
        """直接读取 SQLite，返回 (建表语句, 排序后的全部行)。"""
        conn = self.conn if conn is None else conn
        schema = conn.execute(
            "SELECT sql FROM sqlite_master WHERE name = 'role_permissions'"
        ).fetchone()[0]
        rows = sorted(
            conn.execute("SELECT role FROM role_permissions").fetchall()
        )
        return schema, rows

    # ---- 结构不兼容时的撤销 ----------------------------------------------

    def test_missing_permission_column_raises_storage_error(self):
        # 测试前置：表只有 role 列并保存一行 reader。
        state_before = self.stored_state()
        self.assertEqual(
            state_before,
            (_INCOMPATIBLE_SCHEMA, [("reader",)]),
            f"测试前置：表应只有 role 列并保存一行 reader，"
            f"实际为 {state_before!r}",
        )

        # 缺少 permission 列：必须抛出 StorageError——不得返回 False，
        # 也不得让 sqlite3 原生异常逸出。
        with self.assertRaises(
            store.StorageError,
            msg="缺少 permission 列时应抛出 StorageError 而非返回 False",
        ) as caught:
            store.revoke_permission(self.conn, "reader", PERMISSION_READ)
        self.assertIs(
            type(caught.exception),
            store.StorageError,
            f"异常应恰为 rbac.store.StorageError（不得是 sqlite3 原生异常"
            f"或其子类），实际类型为 {type(caught.exception)!r}",
        )
        self.assertNotIsInstance(
            caught.exception,
            sqlite3.Error,
            f"抛出的异常不得是 sqlite3 原生异常，实际为 {caught.exception!r}",
        )

        # 调用前后表结构与原有记录保持一致。
        self.assertEqual(
            self.stored_state(),
            state_before,
            f"失败后表结构与数据不应变化，之前 {state_before!r}，"
            f"之后 {self.stored_state()!r}",
        )

        # 关闭并重新打开文件：表结构与原有记录仍未改变。
        self.conn.close()
        reopened = sqlite3.connect(self.db_path)
        try:
            state_after_reopen = self.stored_state(reopened)
        finally:
            reopened.close()
        self.assertEqual(
            state_after_reopen,
            state_before,
            f"重新打开后表结构与数据不应变化，之前 {state_before!r}，"
            f"之后 {state_after_reopen!r}",
        )


if __name__ == "__main__":
    unittest.main()
