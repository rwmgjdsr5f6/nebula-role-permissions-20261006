"""rbac.store.grant_permission 同一连接连续授权的存储层回归测试。

不经过命令行子进程，直接传入已规整的合成角色名与权限名调用存储层
函数（名称校验由命令行入口负责，不在本测试范围），核对函数返回值与
落库规则一致、约束冲突失败后同一连接仍可继续合法授权。固定样例：

- 临时 SQLite 文件中 role_permissions 表带 role 单列唯一约束
  （与标准库的复合主键不同），仅预置 (reader, documents:read) 一行；
- 另建 notes 表保存一条固定文本，用于核对失败与重开不影响其他表。

覆盖场景：

- 重复授予已有的 reader/documents:read：返回布尔值 False，规则仍只有
  一条，不增加记录；
- 授予 reader/documents:write 触发单列唯一约束：抛出
  rbac.store.StorageError，不得返回 False，也不得直接抛出 sqlite3
  原生异常；失败前后授权行、role_permissions 与 notes 两张表的结构、
  notes 文本完全一致；
- 捕获异常后继续使用同一连接：授予 editor/documents:read 返回布尔值
  True（实际新增），再次重复授予返回 False（幂等）；
- 关闭并重新打开文件：授权表恰好包含 reader 与 editor 各一条
  documents:read，被约束拒绝的 documents:write 不存在，notes 内容
  不变。

只依赖 Python 3 标准库与 SQLite；每个用例使用独立临时目录，结束时
关闭连接并清理文件，不接触已有规则库。从项目根目录执行：

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

# 固定样例表结构：role 列带单列唯一约束（与标准库的复合主键不同）。
_UNIQUE_ROLE_SCHEMA = (
    "CREATE TABLE role_permissions ("
    "role TEXT NOT NULL UNIQUE, permission TEXT NOT NULL)"
)

# 另一张表与固定文本：核对授权失败与重开不影响规则表之外的数据。
_NOTES_SCHEMA = "CREATE TABLE notes (content TEXT NOT NULL)"
_NOTE_TEXT = "release checklist v1"


class GrantPermissionStoreTests(unittest.TestCase):
    """同一连接上连续调用 grant_permission 的返回值与落库一致性。"""

    def setUp(self):
        # 每个用例独立的临时目录与数据库文件，TemporaryDirectory.cleanup
        # 负责清理；连接在用例结束时关闭释放。
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.db_path = os.path.join(self._tmpdir.name, "rules.db")
        # 准备测试输入：role 单列唯一约束的规则表，仅预置
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
                "INSERT INTO notes (content) VALUES (?)", (_NOTE_TEXT,)
            )
        # 通过现有连接入口打开：CREATE TABLE IF NOT EXISTS 对已有表为
        # 空操作，不改变既有表结构。
        self.conn = store.connect(self.db_path)
        # 用例如需关闭重开会重新赋值 self.conn，清理时关闭当前连接。
        self.addCleanup(lambda: self.conn.close())

    # ---- 辅助方法 -------------------------------------------------------

    def stored_rules(self):
        """直接读取 SQLite，返回排序后的 (role, permission) 授权记录。"""
        return sorted(
            self.conn.execute(
                "SELECT role, permission FROM role_permissions"
            ).fetchall()
        )

    def table_schemas(self):
        """直接读取 SQLite，返回 {表名: 建表语句}（限本样例的两张表）。"""
        rows = self.conn.execute(
            "SELECT name, sql FROM sqlite_master WHERE type = 'table' "
            "AND name IN ('role_permissions', 'notes')"
        ).fetchall()
        return dict(rows)

    def notes_rows(self):
        """直接读取 SQLite，返回 notes 表的全部文本。"""
        return sorted(
            row[0] for row in self.conn.execute("SELECT content FROM notes")
        )

    def stored_state(self):
        """返回 (授权记录, 两表结构, notes 文本) 的完整快照。"""
        return self.stored_rules(), self.table_schemas(), self.notes_rows()

    def assert_state_unchanged(self, state_before, context):
        """核对当前快照与事前一模一样，失败信息指明差异所在。"""
        rules_after, schemas_after, notes_after = self.stored_state()
        rules_before, schemas_before, notes_before = state_before
        self.assertEqual(
            rules_after,
            rules_before,
            f"{context}：授权记录不应变化，之前 {rules_before!r}，"
            f"之后 {rules_after!r}",
        )
        self.assertEqual(
            schemas_after,
            schemas_before,
            f"{context}：两张表的结构不应变化，之前 {schemas_before!r}，"
            f"之后 {schemas_after!r}",
        )
        self.assertEqual(
            notes_after,
            notes_before,
            f"{context}：notes 文本不应变化，之前 {notes_before!r}，"
            f"之后 {notes_after!r}",
        )

    # ---- 幂等重复授权 ----------------------------------------------------

    def test_duplicate_grant_returns_false_and_keeps_single_rule(self):
        state_before = self.stored_state()
        self.assertEqual(
            state_before[0],
            [("reader", PERMISSION_READ)],
            f"测试前置：应只预置 reader/{PERMISSION_READ}，"
            f"实际为 {state_before[0]!r}",
        )

        # 组合已存在：按幂等成功处理，返回布尔值 False（非 None、非 0
        # 之外的假值），且不增加记录。
        result = store.grant_permission(self.conn, "reader", PERMISSION_READ)
        self.assertIs(
            result,
            False,
            f"重复授予已有组合应返回布尔值 False，实际为 {result!r}",
        )

        self.assertEqual(
            self.stored_rules(),
            [("reader", PERMISSION_READ)],
            f"幂等授予后规则仍应只有一条，实际为 {self.stored_rules()!r}",
        )
        self.assert_state_unchanged(state_before, "幂等授予")

    # ---- 约束冲突：StorageError 且状态不变 --------------------------------

    def test_constraint_conflict_raises_storage_error_and_preserves_state(self):
        state_before = self.stored_state()

        # 组合 (reader, documents:write) 不存在，但同一 reader 违反单列
        # 唯一约束：必须抛出 StorageError，不得返回 False，也不得让
        # sqlite3 原生异常漏出。
        try:
            result = store.grant_permission(
                self.conn, "reader", PERMISSION_WRITE
            )
        except store.StorageError as exc:
            self.assertNotIsInstance(
                exc,
                sqlite3.Error,
                f"约束冲突应包装为 StorageError，不应是 sqlite3 原生异常，"
                f"实际类型为 {type(exc).__name__}",
            )
        except sqlite3.Error as exc:
            self.fail(
                f"约束冲突应包装为 StorageError，实际直接抛出 sqlite3 "
                f"原生异常 {type(exc).__name__}: {exc}"
            )
        else:
            self.fail(
                f"约束冲突应抛出 StorageError，实际却返回 {result!r}"
                f"（返回 False 会与幂等成功混淆）"
            )

        # 失败前后的授权行、两张表的结构和 notes 文本保持一致。
        self.assert_state_unchanged(state_before, "约束冲突失败后")

    # ---- 失败后同一连接继续合法授权 ---------------------------------------

    def test_connection_remains_usable_after_constraint_failure(self):
        # 先制造一次约束冲突并捕获。
        with self.assertRaises(
            store.StorageError,
            msg="测试前置：reader/documents:write 应触发约束冲突",
        ):
            store.grant_permission(self.conn, "reader", PERMISSION_WRITE)

        # 捕获异常后继续使用同一连接：新角色 editor 不触发约束，应实际
        # 新增并返回布尔值 True。
        granted = store.grant_permission(self.conn, "editor", PERMISSION_READ)
        self.assertIs(
            granted,
            True,
            f"失败后同一连接授予 editor/{PERMISSION_READ} 应返回布尔值 "
            f"True，实际为 {granted!r}",
        )
        self.assertEqual(
            self.stored_rules(),
            [("editor", PERMISSION_READ), ("reader", PERMISSION_READ)],
            f"editor 的规则应实际落库，实际为 {self.stored_rules()!r}",
        )

        # 再重复授予同一组合：幂等返回 False，记录不再变化。
        regrant = store.grant_permission(self.conn, "editor", PERMISSION_READ)
        self.assertIs(
            regrant,
            False,
            f"重复授予 editor/{PERMISSION_READ} 应返回布尔值 False，"
            f"实际为 {regrant!r}",
        )
        self.assertEqual(
            self.stored_rules(),
            [("editor", PERMISSION_READ), ("reader", PERMISSION_READ)],
            f"幂等授予不应增加记录，实际为 {self.stored_rules()!r}",
        )

    # ---- 关闭重开后核对最终落库状态 ---------------------------------------

    def test_reopen_shows_only_persisted_rules_and_intact_notes(self):
        # 完整走一遍：幂等重复 -> 约束冲突 -> 失败后合法新增。
        self.assertIs(
            store.grant_permission(self.conn, "reader", PERMISSION_READ),
            False,
            "测试前置：重复授予 reader/documents:read 应幂等返回 False",
        )
        with self.assertRaises(
            store.StorageError,
            msg="测试前置：reader/documents:write 应触发约束冲突",
        ):
            store.grant_permission(self.conn, "reader", PERMISSION_WRITE)
        self.assertIs(
            store.grant_permission(self.conn, "editor", PERMISSION_READ),
            True,
            "测试前置：授予 editor/documents:read 应实际新增",
        )

        # 关闭并重新打开同一文件，核对落库结果而非连接缓存。
        self.conn.close()
        self.conn = store.connect(self.db_path)

        self.assertEqual(
            self.stored_rules(),
            [("editor", PERMISSION_READ), ("reader", PERMISSION_READ)],
            f"重开后授权表应恰好包含 reader 与 editor 各一条 "
            f"{PERMISSION_READ}，实际为 {self.stored_rules()!r}",
        )
        self.assertNotIn(
            ("reader", PERMISSION_WRITE),
            self.stored_rules(),
            f"被约束拒绝的 {PERMISSION_WRITE} 不应存在，"
            f"实际为 {self.stored_rules()!r}",
        )
        self.assertEqual(
            self.notes_rows(),
            [_NOTE_TEXT],
            f"重开后 notes 内容不应变化，实际为 {self.notes_rows()!r}",
        )
        self.assertEqual(
            self.table_schemas(),
            {"role_permissions": _UNIQUE_ROLE_SCHEMA, "notes": _NOTES_SCHEMA},
            f"重开后两张表的结构不应变化，实际为 {self.table_schemas()!r}",
        )


if __name__ == "__main__":
    unittest.main()
