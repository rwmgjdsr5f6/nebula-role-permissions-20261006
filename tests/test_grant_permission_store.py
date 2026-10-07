"""rbac.store.grant_permission 同一连接连续授权的存储层回归测试。

不经过命令行子进程，直接调用 rbac.store.grant_permission，在带
role 单列唯一约束的临时 SQLite 规则库上核对返回值与落库规则的一致
性，以及约束拒绝失败后同一连接仍可继续合法授权。覆盖范围：

- 幂等授权：重复授予已存在的 (reader, documents:read) 返回布尔值
  False，规则仍只有一条，不增加记录；
- 约束冲突：授予 (reader, documents:write) 因 role 单列唯一约束被
  拒绝，抛出 rbac.store.StorageError——不得返回 False，也不得直接
  抛出 sqlite3 原生异常；失败前后授权行、role_permissions 与 notes
  两张表的结构、notes 文本均保持不变；
- 失败后连接仍可用：捕获异常后继续使用同一连接，授予
  (editor, documents:read) 返回布尔值 True，再次重复授予返回 False；
- 持久化核对：关闭并重新打开文件后，授权表恰好包含 reader 与 editor
  各一条 documents:read，被拒绝的 documents:write 不存在，
  notes 内容不变。

名称校验由命令行入口负责，本测试只传入已规整的合成名称。只依赖
Python 3 标准库与 SQLite；每个用例使用独立临时目录，结束时关闭连接
并清理文件，不接触已有规则库。从项目根目录执行：

    python -m unittest discover -s tests -p test_grant_permission_store.py
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

# 固定样例：role 列带单列唯一约束（与标准库的复合主键不同），
# 同一角色只能保存一条授权。
_UNIQUE_ROLE_SCHEMA = (
    "CREATE TABLE role_permissions ("
    "role TEXT NOT NULL UNIQUE, permission TEXT NOT NULL)"
)

# 旁列表：用于核对授权失败不影响其他表的结构与内容。
_NOTES_SCHEMA = "CREATE TABLE notes (content TEXT NOT NULL)"
_NOTES_TEXT = "do not touch this note"


class GrantPermissionStoreTests(unittest.TestCase):
    """同一连接上连续调用 grant_permission 的返回值与落库一致性。"""

    def setUp(self):
        # 每个用例独立的临时目录，TemporaryDirectory.cleanup 负责清理。
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.db_path = os.path.join(self._tmpdir.name, "rules.db")
        # 准备测试输入：带单列唯一约束的授权表，预置
        # (reader, documents:read)；notes 表保存一条固定文本。
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(_UNIQUE_ROLE_SCHEMA)
            conn.execute(
                "INSERT INTO role_permissions (role, permission) "
                "VALUES ('reader', ?)",
                (PERMISSION_READ,),
            )
            conn.execute(_NOTES_SCHEMA)
            conn.execute(
                "INSERT INTO notes (content) VALUES (?)", (_NOTES_TEXT,)
            )
        # 通过现有连接入口打开：CREATE TABLE IF NOT EXISTS 对已有表为
        # 空操作，不改变既有表结构。
        self.conn = store.connect(self.db_path)
        self.addCleanup(self.conn.close)

    # ---- 辅助方法 -------------------------------------------------------

    def stored_state(self, conn=None):
        """直接读取 SQLite，返回 (授权行, 建表语句字典, notes 文本列表)。

        授权行按 (role, permission) 排序；建表语句字典覆盖
        role_permissions 与 notes 两张表，用于核对失败前后结构不变。
        """
        conn = self.conn if conn is None else conn
        rows = sorted(
            conn.execute(
                "SELECT role, permission FROM role_permissions"
            ).fetchall()
        )
        schemas = {
            name: sql
            for name, sql in conn.execute(
                "SELECT name, sql FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        notes = [row[0] for row in conn.execute("SELECT content FROM notes")]
        return rows, schemas, notes

    def assert_state_unchanged(self, state_before, context):
        """核对当前数据状态与给定快照完全一致。"""
        self.assertEqual(
            self.stored_state(),
            state_before,
            f"{context}：授权行、两张表结构与 notes 文本均不应变化，"
            f"之前 {state_before!r}，之后 {self.stored_state()!r}",
        )

    # ---- 同一连接连续授权 ----------------------------------------------

    def test_sequential_grants_on_same_connection(self):
        # 测试前置：恰有一条预置规则，两张表结构与 notes 文本就绪。
        state_initial = self.stored_state()
        self.assertEqual(
            state_initial[0],
            [("reader", PERMISSION_READ)],
            f"测试前置：应只预置 reader/{PERMISSION_READ}，"
            f"实际为 {state_initial[0]!r}",
        )
        self.assertEqual(
            state_initial[1],
            {"role_permissions": _UNIQUE_ROLE_SCHEMA, "notes": _NOTES_SCHEMA},
            f"测试前置：两张表的建表语句应保持原样，实际为 {state_initial[1]!r}",
        )
        self.assertEqual(
            state_initial[2],
            [_NOTES_TEXT],
            f"测试前置：notes 应保存固定文本，实际为 {state_initial[2]!r}",
        )

        # 1) 幂等授权：组合已存在，返回布尔值 False 且不增加记录。
        regrant = store.grant_permission(self.conn, "reader", PERMISSION_READ)
        self.assertIs(
            regrant,
            False,
            f"重复授予已有组合应返回布尔值 False，实际为 {regrant!r}",
        )
        self.assert_state_unchanged(state_initial, "幂等授予后")

        # 2) 约束冲突：组合 (reader, documents:write) 不存在，但同一
        #    reader 违反 role 单列唯一约束，必须抛出 StorageError——
        #    不得返回 False，也不得让 sqlite3 原生异常逸出。
        with self.assertRaises(
            store.StorageError,
            msg="约束拒绝新增规则时应抛出 StorageError 而非返回 False",
        ) as caught:
            store.grant_permission(self.conn, "reader", PERMISSION_WRITE)
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

        # 失败前后的授权行、两张表的结构和 notes 文本保持一致。
        self.assert_state_unchanged(state_initial, "约束拒绝授权后")

        # 3) 捕获异常后继续使用同一连接：合法授权应真实持久保存。
        granted = store.grant_permission(self.conn, "editor", PERMISSION_READ)
        self.assertIs(
            granted,
            True,
            f"失败后同一连接授予 editor/{PERMISSION_READ} 应返回布尔值 "
            f"True，实际为 {granted!r}",
        )
        self.assertEqual(
            self.stored_state()[0],
            [("editor", PERMISSION_READ), ("reader", PERMISSION_READ)],
            f"新规则应实际落库，实际授权行为 {self.stored_state()[0]!r}",
        )

        # 4) 再次重复授予同一组合：返回布尔值 False，不增加记录。
        regrant_editor = store.grant_permission(
            self.conn, "editor", PERMISSION_READ
        )
        self.assertIs(
            regrant_editor,
            False,
            f"重复授予 editor/{PERMISSION_READ} 应返回布尔值 False，"
            f"实际为 {regrant_editor!r}",
        )
        self.assertEqual(
            self.stored_state()[0],
            [("editor", PERMISSION_READ), ("reader", PERMISSION_READ)],
            f"幂等授予不应增加记录，实际授权行为 {self.stored_state()[0]!r}",
        )

        # 5) 关闭并重新打开文件：通过新连接核对持久化结果。
        self.conn.close()
        reopened = store.connect(self.db_path)
        try:
            rows, schemas, notes = self.stored_state(reopened)
        finally:
            reopened.close()
        self.assertEqual(
            rows,
            [("editor", PERMISSION_READ), ("reader", PERMISSION_READ)],
            f"重新打开后授权表应恰好包含 reader 与 editor 各一条 "
            f"{PERMISSION_READ}，实际为 {rows!r}",
        )
        self.assertNotIn(
            PERMISSION_WRITE,
            [permission for _, permission in rows],
            f"被约束拒绝的 {PERMISSION_WRITE} 不应持久保存，实际为 {rows!r}",
        )
        self.assertEqual(
            schemas,
            {"role_permissions": _UNIQUE_ROLE_SCHEMA, "notes": _NOTES_SCHEMA},
            f"重新打开后两张表结构应保持原样，实际为 {schemas!r}",
        )
        self.assertEqual(
            notes,
            [_NOTES_TEXT],
            f"重新打开后 notes 内容不应变化，实际为 {notes!r}",
        )

    def test_failed_grant_does_not_poison_connection(self):
        # 约束拒绝后同一连接上的只读查询与后续授权均不受影响。
        with self.assertRaises(store.StorageError):
            store.grant_permission(self.conn, "reader", PERMISSION_WRITE)

        self.assertEqual(
            store.list_permissions(self.conn, "reader"),
            [PERMISSION_READ],
            f"失败后 list_permissions 应仍只返回预置权限，"
            f"实际为 {store.list_permissions(self.conn, 'reader')!r}",
        )
        self.assertIs(
            store.grant_permission(self.conn, "editor", PERMISSION_READ),
            True,
            "失败后同一连接的合法授权应返回布尔值 True",
        )
        self.assertIs(
            store.grant_permission(self.conn, "editor", PERMISSION_READ),
            False,
            "同一组合再次授予应返回布尔值 False",
        )


if __name__ == "__main__":
    unittest.main()
