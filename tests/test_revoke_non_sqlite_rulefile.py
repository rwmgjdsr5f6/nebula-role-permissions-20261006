"""revoke 面对无效规则文件（内容不是 SQLite 数据库）时的命令行回归测试。

在既有“正常撤销”和“授权、成员汇总访问非数据库文件”测试之外，补齐 revoke
在非 SQLite 规则文件上的存储错误协议。测试输入：父目录存在，rules.db 文件
也存在，但内容固定为连续 128 个 ASCII 字符 x，且从未用 SQLite 初始化过
（不是 SQLite 数据库文件）。此时数据库能够建立连接，但建表初始化
（CREATE TABLE IF NOT EXISTS）必然失败，store.connect 统一包装为
StorageError，命令行必须遵守既有错误协议：

- revoke reader documents:read：退出码 1，标准输出为空，标准错误恰为
  {"error":"storage_error"} 加换行，不附加错误详情或异常堆栈；不得用
  revoked=false 的正常结果替代存储失败；
- 角色名或权限名带首尾空格、制表符，但去除空白后仍有效时（如
  " reader "、"\\tdocuments:read\\t"），规整在进程内完成，存储访问
  依旧失败，同样得到上述存储错误；
- 角色名和权限名分别传入空字符串、纯空白时：名称校验优先于存储访问，
  退出码 2，stdout 为空，stderr 恰为 {"error":"invalid_name"} 加换行，
  不打开规则存储做业务操作。

每次调用前后都核对规则文件仍然存在且全部字节相同（仍是那 128 个 x），
即失败不得删除、清空、覆盖、截断、重新初始化或“修补”文件。在同一文件上
连续两次执行有效的撤销请求，两次都必须独立返回存储错误，第一次失败不得
改变第二次的行为。

只依赖 Python 3 标准库；每个用例使用独立临时目录，结束后自动清理。
从项目根目录执行：

    python -m unittest discover -s tests
"""

import os
import subprocess
import sys
import tempfile
import unittest

# tests/ 的上一级即项目根目录（rbac 包所在目录）。
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PERMISSION_READ = "documents:read"
ROLE_READER = "reader"
STORAGE_ERROR = '{"error":"storage_error"}\n'
INVALID_NAME_ERROR = '{"error":"invalid_name"}\n'

# 非数据库文件的固定内容：连续 128 个 ASCII 字符 x，绝不经过 SQLite 初始化。
_NON_SQLITE_BYTES = b"x" * 128


class RevokeNonSqliteRuleFileTests(unittest.TestCase):
    """通过 `python -m rbac` 子进程核对 revoke 在非 SQLite 规则文件上的行为。"""

    def setUp(self):
        # 每个用例独立的临时目录，TemporaryDirectory.cleanup 负责清理。
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.tmpdir = self._tmpdir.name
        self.db_path = os.path.join(self.tmpdir, "rules.db")
        self.write_non_sqlite_file()

    # ---- 辅助方法 -------------------------------------------------------

    def write_non_sqlite_file(self):
        """直接写入固定的非数据库字节，不使用 sqlite3 初始化该文件。"""
        with open(self.db_path, "wb") as handle:
            handle.write(_NON_SQLITE_BYTES)

    def run_rbac(self, *argv):
        """运行 rbac revoke 命令行，返回 CompletedProcess（文本模式、UTF-8）。"""
        command = [
            sys.executable,
            "-m",
            "rbac",
            "--db",
            self.db_path,
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

    def rule_file_bytes(self):
        """返回规则文件当前字节；文件缺失时返回 None。"""
        if not os.path.exists(self.db_path):
            return None
        with open(self.db_path, "rb") as handle:
            return handle.read()

    def assert_file_unchanged(self, snapshot, argv):
        """调用后规则文件必须仍存在，且全部字节与调用前完全相同。"""
        self.assertTrue(
            os.path.exists(self.db_path),
            f"输入 {argv!r}：调用后规则文件 {self.db_path!r} 不应消失",
        )
        after = self.rule_file_bytes()
        self.assertEqual(
            after,
            snapshot,
            f"输入 {argv!r}：调用前后规则文件字节必须完全相同，"
            f"调用前 {len(snapshot)} 字节，调用后 "
            f"{0 if after is None else len(after)} 字节",
        )
        # 显式钉死：仍是最初那 128 个 ASCII x，未被删除、截断或修补为数据库。
        self.assertEqual(
            after,
            _NON_SQLITE_BYTES,
            f"输入 {argv!r}：规则文件内容应保持为 128 个 ASCII x，"
            f"实际为 {after!r}",
        )

    def assert_storage_error(self, proc, argv):
        """存储失败：退出码 1，stdout 为空，stderr 仅为固定错误行。

        标准输出为空即排除了任何正常业务结果（含 revoked=false 的
        “规则不存在”成功结果）被当作替代输出的可能。
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
        # 存储失败不得伪装成“规则不存在”的正常撤销结果。
        self.assertNotIn(
            "revoked",
            proc.stdout,
            f"输入 {argv!r}：存储失败不得以 revoked 字段（含 revoked=false）"
            f"替代，实际 stdout={proc.stdout!r}",
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
        self.assertNotIn(
            "Traceback",
            proc.stderr,
            f"输入 {argv!r}：标准错误不得包含异常堆栈，实际为 {proc.stderr!r}",
        )

    # ---- 测试前置 --------------------------------------------------------

    def test_precondition_parent_dir_and_file_exist_with_128_ascii_x(self):
        # 钉死测试输入：父目录存在、rules.db 存在、恰为 128 个 ASCII x，
        # 且不含 SQLite 头部，保证后续失败确实来自“内容不是数据库”。
        self.assertTrue(
            os.path.isdir(self.tmpdir), "测试前置：父目录应已存在"
        )
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

    # ---- 非 SQLite 文件上的撤销存储失败 ----------------------------------

    def test_revoke_on_non_sqlite_file_is_storage_error_and_preserves_bytes(self):
        snapshot = self.rule_file_bytes()

        argv = ("revoke", ROLE_READER, PERMISSION_READ)
        proc = self.run_rbac(*argv)
        self.assert_storage_error(proc, argv)

        # 撤销成功 JSON（role/permission/revoked）不得出现：stdout 必须为空。
        self.assertNotIn(
            "role",
            proc.stdout,
            f"输入 {argv!r}：存储失败不得输出撤销结果，实际为 {proc.stdout!r}",
        )
        self.assertNotIn(
            "permission",
            proc.stdout,
            f"输入 {argv!r}：存储失败不得输出撤销结果，实际为 {proc.stdout!r}",
        )
        self.assert_file_unchanged(snapshot, argv)

    def test_revoke_with_surrounding_whitespace_is_storage_error(self):
        # 名称带首尾空格、制表符但去除后仍有效：规整在进程内完成，
        # 随后的存储访问依旧在非数据库文件上失败，必须报 storage_error
        # 而非 invalid_name，也不得返回 revoked=false。
        cases = [
            ("revoke", " " + ROLE_READER + " ", PERMISSION_READ),
            ("revoke", "\t" + ROLE_READER + "\t", PERMISSION_READ),
            ("revoke", ROLE_READER, " " + PERMISSION_READ + " "),
            ("revoke", ROLE_READER, "\t" + PERMISSION_READ + "\t"),
            ("revoke", " " + ROLE_READER + " ", "\t " + PERMISSION_READ + " \t"),
        ]
        for argv in cases:
            with self.subTest(argv=argv):
                snapshot = self.rule_file_bytes()
                proc = self.run_rbac(*argv)
                self.assert_storage_error(proc, argv)
                self.assert_file_unchanged(snapshot, argv)

    # ---- 名称无效与名称有效的区别：校验优先于存储访问 --------------------

    def test_revoke_blank_role_or_permission_is_invalid_and_preserves_bytes(self):
        # 角色名和权限名分别传入空字符串与纯空白：即使文件不是数据库，
        # 也必须优先判定 invalid_name（退出码 2），不访问规则存储，
        # 且全程不改动文件字节。
        cases = [
            ("revoke", "", PERMISSION_READ),
            ("revoke", "   ", PERMISSION_READ),
            ("revoke", "\t \n", PERMISSION_READ),
            ("revoke", ROLE_READER, ""),
            ("revoke", ROLE_READER, "   "),
            ("revoke", ROLE_READER, "\t\t "),
        ]
        for argv in cases:
            with self.subTest(argv=argv):
                snapshot = self.rule_file_bytes()
                proc = self.run_rbac(*argv)
                self.assert_invalid_name(proc, argv)
                self.assert_file_unchanged(snapshot, argv)

    def test_invalid_name_takes_precedence_and_storage_is_not_reported(self):
        # 同一非数据库文件既能触发 storage_error 也能触发 invalid_name 时，
        # 非法名称必须优先：退出码与错误行都只能是 invalid_name。
        argv = ("revoke", "   ", "   ")
        snapshot = self.rule_file_bytes()
        proc = self.run_rbac(*argv)
        self.assert_invalid_name(proc, argv)
        self.assertNotIn(
            "storage_error",
            proc.stderr,
            f"输入 {argv!r}：非法名称优先，不得同时报 storage_error，"
            f"实际 stderr={proc.stderr!r}",
        )
        self.assert_file_unchanged(snapshot, argv)

    # ---- 同一文件连续两次撤销：失败相互独立，文件不被修补 ----------------

    def test_two_consecutive_revokes_both_fail_and_file_never_reinitialized(self):
        # 连续两次执行有效的撤销请求：两次都必须独立返回存储错误；
        # 第一次失败不得删除、截断或重新初始化文件，从而改变第二次行为。
        for attempt in (1, 2):
            argv = ("revoke", ROLE_READER, PERMISSION_READ)
            with self.subTest(attempt=attempt):
                snapshot = self.rule_file_bytes()
                proc = self.run_rbac(*argv)
                self.assert_storage_error(proc, argv)
                self.assert_file_unchanged(snapshot, argv)

        # 两次调用之后，文件依旧存在且仍是最初的 128 个 x。
        self.assertTrue(
            os.path.isfile(self.db_path),
            "连续两次撤销失败后规则文件仍应存在",
        )
        final_bytes = self.rule_file_bytes()
        self.assertEqual(
            final_bytes,
            _NON_SQLITE_BYTES,
            f"连续两次失败后文件应仍是 128 个 ASCII x，实际为 {final_bytes!r}",
        )
        self.assertEqual(len(final_bytes), 128)
        self.assertFalse(
            final_bytes.startswith(b"SQLite format 3"),
            "失败不得把文件重新初始化为 SQLite 数据库",
        )


if __name__ == "__main__":
    unittest.main()
