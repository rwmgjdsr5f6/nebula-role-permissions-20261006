"""rbac.store.revoke_permission 直接调用的存储层回归测试。

不经过命令行子进程，直接调用 rbac.store.revoke_permission，在独立
临时 SQLite 规则库上核对返回值、真实删除与持久化结果的一致性。覆盖
范围：

- 真实删除：预置 reader/documents:read、reader/documents:write、
  editor/documents:read 三条规则，撤销第一条返回布尔值 True，剩余
  规则恰好为另外两条——完整规则集合比对可同时发现漏删与误删其他
  授权；
- 幂等撤销：重复撤销同一组合返回布尔值 False，记录不再变化；
- 未授权组合：撤销从未授权的 ghost/documents:read 返回布尔值
  False，记录不变；
- 持久化核对：关闭连接并重新打开文件后，删除结果仍然有效，剩余
  规则完全一致；
- 结构不兼容：role_permissions 表缺少 permission 列时，撤销必须
  抛出 rbac.store.StorageError——不得返回 False，也不得让 sqlite3
  原生异常逸出；调用前后及重新打开后表结构与原有记录均不改变。

名称规整（首尾空白处理与 invalid_name 判定）由命令行入口负责，本
测试只传入已规整的合成名称。只依赖 Python 3 标准库与 SQLite；每个
用例使用独立临时目录，结束时关闭连接并清理文件，不接触已有规则库。
从项目根目录执行：

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

# 预置的三条授权规则及其撤销第一条后的剩余集合（按 (role, permission)
# 排序，与 stored_rules 的输出顺序一致）。
_SEEDED_RULES = [
    ("editor", PERMISSION_READ),
    ("reader", PERMISSION_READ),
    ("reader", PERMISSION_WRITE),
]
_REMAINING_RULES = [
    ("editor", PERMISSION_READ),
    ("reader", PERMISSION_WRITE),
]

# 不兼容的表结构：只有 role 列，缺少业务所需的 permission 列。
_INCOMPATIBLE_SCHEMA = "CREATE TABLE role_permissions (role TEXT)"


class RevokePermissionStoreTests(unittest.TestCase):
    """同一连接上连续撤销的返回值、落库规则与持久化一致性。"""

    def setUp(self):
        # 每个用例独立的临时目录，TemporaryDirectory.cleanup 负责清理。
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.db_path = os.path.join(self._tmpdir.name, "rules.db")
        # 通过现有连接入口创建标准表结构，再预置三条授权规则。
        self.conn = store.connect(self.db_path)
        self.addCleanup(self.conn.close)
        for role, permission in _SEEDED_RULES:
            self.conn.execute(
                "INSERT INTO role_permissions (role, permission) "
                "VALUES (?, ?)",
                (role, permission),
            )
        self.conn.commit()

    # ---- 辅助方法 -------------------------------------------------------

    def stored_rules(self, conn=None):
        """直接读取 SQLite，返回按 (role, permission) 排序的完整规则列表。"""
        conn = self.conn if conn is None else conn
        return sorted(
            conn.execute(
                "SELECT role, permission FROM role_permissions"
            ).fetchall()
        )

    # ---- 撤销、幂等与持久化 ---------------------------------------------

    def test_revoke_idempotent_and_persisted(self):
        # 测试前置：三条预置规则全部就位。
        self.assertEqual(
            self.stored_rules(),
            _SEEDED_RULES,
            f"测试前置：应预置三条规则 {_SEEDED_RULES!r}，"
            f"实际为 {self.stored_rules()!r}",
        )

        # 1) 真实删除：撤销 (reader, documents:read) 返回布尔值 True，
        #    剩余规则恰好为另外两条——完整集合比对可同时发现漏删与
        #    误删其他授权。
        revoked = store.revoke_permission(self.conn, "reader", PERMISSION_READ)
        self.assertIs(
            revoked,
            True,
            f"撤销已存在的 reader/{PERMISSION_READ} 应返回布尔值 True，"
            f"实际为 {revoked!r}",
        )
        self.assertEqual(
            self.stored_rules(),
            _REMAINING_RULES,
            f"撤销后剩余规则应恰好为 {_REMAINING_RULES!r}，"
            f"实际为 {self.stored_rules()!r}",
        )

        # 2) 幂等撤销：重复撤销同一组合返回布尔值 False，记录不再变化。
        revoked_again = store.revoke_permission(
            self.conn, "reader", PERMISSION_READ
        )
        self.assertIs(
            revoked_again,
            False,
            f"重复撤销同一组合应返回布尔值 False，实际为 {revoked_again!r}",
        )
        self.assertEqual(
            self.stored_rules(),
            _REMAINING_RULES,
            f"幂等撤销不应改变记录，实际为 {self.stored_rules()!r}",
        )

        # 3) 未授权组合：ghost 从未获授 documents:read，撤销返回布尔值
        #    False，记录不变。
        revoked_ghost = store.revoke_permission(
            self.conn, "ghost", PERMISSION_READ
        )
        self.assertIs(
            revoked_ghost,
            False,
            f"撤销从未授权的 ghost/{PERMISSION_READ} 应返回布尔值 False，"
            f"实际为 {revoked_ghost!r}",
        )
        self.assertEqual(
            self.stored_rules(),
            _REMAINING_RULES,
            f"撤销未授权组合不应改变记录，实际为 {self.stored_rules()!r}",
        )

        # 4) 关闭并重新打开文件：通过新连接核对删除结果仍然有效，
        #    剩余规则完全一致。
        self.conn.close()
        reopened = store.connect(self.db_path)
        try:
            persisted_rules = self.stored_rules(reopened)
        finally:
            reopened.close()
        self.assertEqual(
            persisted_rules,
            _REMAINING_RULES,
            f"重新打开后剩余规则应仍为 {_REMAINING_RULES!r}，"
            f"实际为 {persisted_rules!r}",
        )


class RevokePermissionMissingColumnTests(unittest.TestCase):
    """缺少 permission 列时撤销必须抛出 StorageError 且不改变数据。"""

    def setUp(self):
        # 每个用例独立的临时目录，TemporaryDirectory.cleanup 负责清理。
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.db_path = os.path.join(self._tmpdir.name, "rules.db")
        # 准备测试输入：role_permissions 表只有 role 列，保存一行 reader。
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(_INCOMPATIBLE_SCHEMA)
            conn.execute("INSERT INTO role_permissions (role) VALUES ('reader')")
        # 通过现有连接入口打开：CREATE TABLE IF NOT EXISTS 对已有表为
        # 空操作，不改变既有表结构。
        self.conn = store.connect(self.db_path)
        self.addCleanup(self.conn.close)

    # ---- 辅助方法 -------------------------------------------------------

    def stored_state(self, conn=None):
        """直接读取 SQLite，返回 (role 列记录, 建表语句字典)。"""
        conn = self.conn if conn is None else conn
        rows = conn.execute("SELECT role FROM role_permissions").fetchall()
        schemas = {
            name: sql
            for name, sql in conn.execute(
                "SELECT name, sql FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        return rows, schemas

    # ---- 结构不兼容时的失败协议 -----------------------------------------

    def test_missing_permission_column_raises_storage_error(self):
        # 测试前置：表结构只有 role 列，恰有一行 reader。
        state_before = self.stored_state()
        self.assertEqual(
            state_before,
            ([("reader",)], {"role_permissions": _INCOMPATIBLE_SCHEMA}),
            f"测试前置：应只有一行 reader 且表结构保持原样，"
            f"实际为 {state_before!r}",
        )

        # 缺少 permission 列，撤销必须抛出 rbac.store.StorageError——
        # 不得返回 False，也不得让 sqlite3 原生异常逸出。
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

        # 调用前后表结构与原有记录均未改变。
        self.assertEqual(
            self.stored_state(),
            state_before,
            f"抛出 StorageError 后表结构与记录不应变化，"
            f"之前 {state_before!r}，之后 {self.stored_state()!r}",
        )

        # 关闭并重新打开文件：表结构与原有记录仍然保持一致。
        self.conn.close()
        reopened = store.connect(self.db_path)
        try:
            persisted_state = self.stored_state(reopened)
        finally:
            reopened.close()
        self.assertEqual(
            persisted_state,
            state_before,
            f"重新打开后表结构与记录应仍为 {state_before!r}，"
            f"实际为 {persisted_state!r}",
        )


if __name__ == "__main__":
    unittest.main()
