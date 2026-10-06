"""规则文件内容不是 SQLite 数据库时的命令行回归测试。

测试输入：父目录存在，rules.db 文件也存在，但内容固定为连续 128 个 ASCII
字符 x，且从未用 SQLite 初始化过（不是 SQLite 数据库文件）。此时数据库
能够建立连接，但建表初始化（CREATE TABLE IF NOT EXISTS）必然失败，
store.connect 统一包装为 StorageError，命令行必须遵守既有错误协议：

- grant reader documents:read：退出码 1，标准输出为空，标准错误恰为
  {"error":"storage_error"} 加换行，不附加错误详情或异常堆栈；
- list-member-permissions bob：bob 没有配置任何角色，正常情况下应得到
  空权限汇总，但连接在业务查询之前就已失败，因此这里同样必须是存储失败
  （退出码 1、stdout 为空、stderr 为固定错误行），不能输出正常的
  {"member":"bob","roles":[],"permissions":[]}；
- grant 的角色名或权限名、成员汇总的成员名分别传入空字符串及纯空白：
  名称校验优先于存储访问，退出码 2，stdout 为空，stderr 恰为
  {"error":"invalid_name"} 加换行，不打开存储语义上的业务操作。

每次调用前后都核对规则文件仍然存在且全部字节相同（仍是那 128 个 x），
即失败不得清空、覆盖、截断或修补文件。另设正常结果对照：在另一个已存在
的临时目录中查询尚不存在的规则文件（成员 bob），应退出码 0、stderr 为空、
stdout 恰为 {"member":"bob","roles":[],"permissions":[]} 加换行，并按
现有行为把规则文件初始化为可用的 SQLite 数据库。

只依赖 Python 3 标准库；每个用例使用独立临时目录与合成名称，结束后自动
清理。从项目根目录执行：

    python -m unittest discover -s tests
"""

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest

# tests/ 的上一级即项目根目录（rbac 包所在目录）。
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PERMISSION_READ = "documents:read"
STORAGE_ERROR = '{"error":"storage_error"}\n'
INVALID_NAME_ERROR = '{"error":"invalid_name"}\n'
BOB_EMPTY_SUMMARY = '{"member":"bob","roles":[],"permissions":[]}\n'

# 非数据库文件的固定内容：连续 128 个 ASCII 字符 x，绝不经过 SQLite 初始化。
_NON_SQLITE_BYTES = b"x" * 128


class NonSqliteRuleFileTests(unittest.TestCase):
    """通过 `python -m rbac` 子进程核对非 SQLite 规则文件上的对外行为。"""

    def setUp(self):
        # 每个用例独立的临时目录，TemporaryDirectory.cleanup 负责清理。
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.tmpdir = self._tmpdir.name
        self.db_path = os.path.join(self.tmpdir, "rules.db")
        self.write_non_sqlite_file()

    # ---- 辅助方法 -------------------------------------------------------

    def write_non_sqlite_file(self, path=None):
        """直接写入固定的非数据库字节，不使用 sqlite3 初始化该文件。"""
        target = self.db_path if path is None else path
        with open(target, "wb") as handle:
            handle.write(_NON_SQLITE_BYTES)

    def run_rbac(self, *argv, db=None):
        """运行 rbac 命令行，返回 CompletedProcess（文本模式、UTF-8）。"""
        command = [
            sys.executable,
            "-m",
            "rbac",
            "--db",
            self.db_path if db is None else db,
            *argv,
        ]
        # 显式注入 PYTHONPATH，使任意当前工作目录下都能找到 rbac 包。
        pythonpath = PROJECT_ROOT
        old_pythonpath = os.environ.get("PYTHONPATH")
        if old_pythonpath:
            pythonpath = os.pathsep.join((pythonpath, old_pythonpath))
        env = dict(os.environ, PYTHONPATH=pythonpath)
        return subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )

    def rule_file_bytes(self, path=None):
        """返回规则文件当前字节；文件缺失时返回 None。"""
        target = self.db_path if path is None else path
        if not os.path.exists(target):
            return None
        with open(target, "rb") as handle:
            return handle.read()

    def assert_file_unchanged(self, snapshot, argv, path=None):
        """调用后规则文件必须仍存在，且全部字节与调用前完全相同。"""
        target = self.db_path if path is None else path
        self.assertTrue(
            os.path.exists(target),
            f"输入 {argv!r}：调用后规则文件 {target!r} 不应消失",
        )
        after = self.rule_file_bytes(target)
        self.assertEqual(
            after,
            snapshot,
            f"输入 {argv!r}：调用前后规则文件字节必须完全相同，"
            f"调用前 {len(snapshot)} 字节，调用后 "
            f"{0 if after is None else len(after)} 字节",
        )
        # 显式钉死：仍是最初那 128 个 ASCII x，未被清空或修补为数据库。
        self.assertEqual(
            after,
            _NON_SQLITE_BYTES,
            f"输入 {argv!r}：规则文件内容应保持为 128 个 ASCII x，"
            f"实际为 {after!r}",
        )

    def assert_storage_error(self, proc, argv):
        """存储失败：退出码 1，stdout 为空，stderr 仅为固定错误行。

        标准输出为空即排除了任何正常业务结果（成功授权、空权限汇总）
        被当作替代输出的可能。
        """
        self.assertEqual(
            proc.returncode,
            1,
            f"输入 {argv!r}：期望退出码 1，实际 {proc.returncode}，"
            f"stdout={proc.stdout!r}，stderr={proc.stderr!r}",
        )
        self.assertEqual(
            proc.stdout,
            "",
            f"输入 {argv!r}：storage_error 时标准输出应为空（不得夹带业务结果），"
            f"实际为 {proc.stdout!r}",
        )
        self.assertEqual(
            proc.stderr,
            STORAGE_ERROR,
            f"输入 {argv!r}：标准错误应恰为 {STORAGE_ERROR!r}"
            f"（不附加详情或堆栈），实际为 {proc.stderr!r}",
        )
        self.assertNotIn(
            "Traceback",
            proc.stderr,
            f"输入 {argv!r}：标准错误不得包含异常堆栈，实际为 {proc.stderr!r}",
        )

    def assert_invalid_name(self, proc, argv):
        """空名称/纯空白：退出码 2，stdout 为空，stderr 仅为固定错误行。"""
        self.assertEqual(
            proc.returncode,
            2,
            f"输入 {argv!r}：期望退出码 2，实际 {proc.returncode}，"
            f"stdout={proc.stdout!r}，stderr={proc.stderr!r}",
        )
        self.assertEqual(
            proc.stdout,
            "",
            f"输入 {argv!r}：invalid_name 时标准输出应为空，实际为 {proc.stdout!r}",
        )
        self.assertEqual(
            proc.stderr,
            INVALID_NAME_ERROR,
            f"输入 {argv!r}：标准错误应恰为 {INVALID_NAME_ERROR!r}"
            f"（名称校验优先于存储访问），实际为 {proc.stderr!r}",
        )

    # ---- 测试前置 --------------------------------------------------------

    def test_precondition_file_is_exactly_128_ascii_x_without_sqlite_header(self):
        # 钉死测试输入：文件存在、恰为 128 个 ASCII x，且不含 SQLite 头部，
        # 保证后续失败确实来自“内容不是数据库”，而非其他前置状态。
        self.assertTrue(os.path.isfile(self.db_path), "测试前置：rules.db 应已存在")
        data = self.rule_file_bytes()
        self.assertEqual(len(data), 128, f"文件应恰为 128 字节，实际为 {len(data)}")
        self.assertEqual(data, _NON_SQLITE_BYTES)
        self.assertTrue(
            all(0x21 <= byte <= 0x7E for byte in data),
            "文件内容应全部为可打印 ASCII 字符",
        )
        self.assertFalse(
            data.startswith(b"SQLite format 3"),
            "文件不得是经过 SQLite 初始化的数据库",
        )

    # ---- 非 SQLite 文件上的存储失败 --------------------------------------

    def test_grant_on_non_sqlite_file_is_storage_error_and_preserves_bytes(self):
        snapshot = self.rule_file_bytes()

        argv = ("grant", "reader", PERMISSION_READ)
        proc = self.run_rbac(*argv)
        self.assert_storage_error(proc, argv)

        # 授权成功 JSON 不得出现：stdout 必须为空。
        self.assertNotIn(
            "role",
            proc.stdout,
            f"输入 {argv!r}：存储失败不得输出授权结果，实际为 {proc.stdout!r}",
        )
        self.assert_file_unchanged(snapshot, argv)

    def test_bob_summary_on_non_sqlite_file_is_storage_error_not_empty_success(self):
        # bob 没有配置角色：正常库上会直接得到空权限汇总；但非 SQLite 文件
        # 在业务查询前的连接初始化阶段就已失败，必须报告存储失败，
        # 不能输出正常的空权限汇总。
        snapshot = self.rule_file_bytes()

        argv = ("list-member-permissions", "bob")
        proc = self.run_rbac(*argv)
        self.assert_storage_error(proc, argv)

        self.assertNotEqual(
            proc.stdout,
            BOB_EMPTY_SUMMARY,
            f"输入 {argv!r}：非数据库文件上不得输出 bob 的正常空权限汇总，"
            f"实际 stdout={proc.stdout!r}",
        )
        self.assertNotIn(
            "permissions",
            proc.stdout,
            f"输入 {argv!r}：存储失败不得输出 permissions 字段"
            f"（不能把读取失败伪装成没有权限），实际为 {proc.stdout!r}",
        )
        self.assertNotIn(
            "member",
            proc.stdout,
            f"输入 {argv!r}：存储失败不得输出成员汇总，实际为 {proc.stdout!r}",
        )
        self.assert_file_unchanged(snapshot, argv)

    def test_both_storage_failures_reported_on_same_non_sqlite_file(self):
        # 同一非数据库文件上连续调用：grant 与 bob 汇总都必须失败，
        # 每次调用前后字节都保持原样，互相不“修复”文件。
        for argv in (
            ("grant", "reader", PERMISSION_READ),
            ("list-member-permissions", "bob"),
        ):
            with self.subTest(argv=argv):
                snapshot = self.rule_file_bytes()
                proc = self.run_rbac(*argv)
                self.assert_storage_error(proc, argv)
                self.assert_file_unchanged(snapshot, argv)

        # 两次调用之后，文件依旧是最初的 128 个 x。
        self.assertEqual(self.rule_file_bytes(), _NON_SQLITE_BYTES)

    # ---- 名称校验优先于存储失败 ------------------------------------------

    def test_grant_blank_role_or_permission_is_invalid_and_preserves_bytes(self):
        # 角色或权限分别为空字符串与纯空白：即使文件不是数据库，
        # 也必须优先判定 invalid_name，且全程不改动文件字节。
        cases = [
            ("grant", "", PERMISSION_READ),
            ("grant", "   ", PERMISSION_READ),
            ("grant", "reader", ""),
            ("grant", "reader", "\t \n"),
        ]
        for argv in cases:
            with self.subTest(argv=argv):
                snapshot = self.rule_file_bytes()
                proc = self.run_rbac(*argv)
                self.assert_invalid_name(proc, argv)
                self.assert_file_unchanged(snapshot, argv)

    def test_blank_member_summary_is_invalid_and_preserves_bytes(self):
        # 成员名为空字符串或纯空白：优先 invalid_name，文件字节不变。
        for member in ("", "   ", "\t \n"):
            argv = ("list-member-permissions", member)
            with self.subTest(argv=argv):
                snapshot = self.rule_file_bytes()
                proc = self.run_rbac(*argv)
                self.assert_invalid_name(proc, argv)
                self.assert_file_unchanged(snapshot, argv)

    # ---- 正常结果对照：另一个目录中尚不存在的规则文件 --------------------

    def test_missing_db_in_another_directory_initializes_and_bob_succeeds(self):
        # 对照：在另一个已存在的临时目录中，规则文件尚不存在。
        # 查询 bob 应成功返回空汇总，并按现有行为初始化规则文件。
        control_dir = tempfile.TemporaryDirectory()
        self.addCleanup(control_dir.cleanup)
        fresh_db = os.path.join(control_dir.name, "rules.db")
        self.assertTrue(
            os.path.isdir(control_dir.name), "测试前置：对照目录应已存在"
        )
        self.assertFalse(
            os.path.exists(fresh_db), "测试前置：对照规则文件应尚不存在"
        )

        argv = ("list-member-permissions", "bob")
        proc = self.run_rbac(*argv, db=fresh_db)

        self.assertEqual(
            proc.returncode,
            0,
            f"输入 {argv!r}：期望退出码 0，实际 {proc.returncode}，"
            f"stdout={proc.stdout!r}，stderr={proc.stderr!r}",
        )
        self.assertEqual(
            proc.stderr,
            "",
            f"输入 {argv!r}：成功时标准错误应为空，实际为 {proc.stderr!r}",
        )
        # 字节形态恰为既有紧凑 UTF-8 JSON 加一个换行。
        self.assertEqual(
            proc.stdout,
            BOB_EMPTY_SUMMARY,
            f"输入 {argv!r}：标准输出应恰为 {BOB_EMPTY_SUMMARY!r}，"
            f"实际为 {proc.stdout!r}",
        )
        self.assertEqual(
            json.loads(proc.stdout),
            {"member": "bob", "roles": [], "permissions": []},
            f"输入 {argv!r}：解析后的汇总与预期不符，实际为 {proc.stdout!r}",
        )

        # 按现有行为：规则文件被初始化为可用的 SQLite 数据库。
        self.assertTrue(
            os.path.exists(fresh_db),
            f"输入 {argv!r}：查询应初始化规则文件 {fresh_db!r}",
        )
        with sqlite3.connect(fresh_db) as conn:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            self.assertIn(
                "role_permissions",
                tables,
                f"初始化后的库应包含 role_permissions 表，实际表为 {tables!r}",
            )
            # 初始化出的空库可直接用于业务查询。
            rows = conn.execute(
                "SELECT role, permission FROM role_permissions"
            ).fetchall()
        self.assertEqual(rows, [], "新初始化的规则文件不应包含任何授权记录")

        # 对照目录的初始化不影响非 SQLite 文件：字节保持原样。
        self.assertEqual(
            self.rule_file_bytes(),
            _NON_SQLITE_BYTES,
            "对照用例不得改动非 SQLite 规则文件的内容",
        )


if __name__ == "__main__":
    unittest.main()
