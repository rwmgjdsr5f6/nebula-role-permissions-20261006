"""撤销命令面对无效（非 SQLite）规则文件时的命令行回归测试。

现有 test_non_sqlite_rulefile.py 已覆盖 grant 与成员汇总在非数据库文件上的
行为；本文件专门补齐 revoke：

测试输入：父目录存在，rules.db 文件也存在，但内容固定为连续 128 个 ASCII
字符 x，且从未用 SQLite 初始化过（不是 SQLite 数据库文件）。此时数据库
能够建立连接，但建表初始化（CREATE TABLE IF NOT EXISTS）必然失败，
store.connect 统一包装为 StorageError。在此前提下调用

    python -m rbac --db rules.db revoke reader documents:read

必须遵守既有错误协议：退出码 1，标准输出为空，标准错误恰为
{"error":"storage_error"} 加换行，不附加错误详情或异常堆栈，也不能以
正常业务结果 revoked=false 替代存储失败。

名称有效与名称无效的区别：

- 角色名或权限名带首尾空格、制表符，但去除空白后仍有效时（如
  "  reader  "、"\\tdocuments:read\\t"），规整后照常访问存储，同样得到
  上述存储错误；
- 角色名和权限名分别传入空字符串、纯空白（"   "、"\\t \\n"）时，名称校验
  优先于存储访问：退出码 2，stdout 为空，stderr 恰为
  {"error":"invalid_name"} 加换行，且不访问规则存储。

每次调用前后都核对规则文件仍然存在且全部字节完全相同（仍是那 128 个 x），
即失败不得删除、清空、覆盖、截断或把文件重新初始化为数据库。在同一文件上
连续两次执行有效的撤销请求，两次均应独立返回存储错误，第一次失败不得改变
第二次的结果或文件状态。

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

ROLE_READER = "reader"
PERMISSION_READ = "documents:read"
STORAGE_ERROR = '{"error":"storage_error"}\n'
INVALID_NAME_ERROR = '{"error":"invalid_name"}\n'

# 非数据库文件的固定内容：连续 128 个 ASCII 字符 x，绝不经过 SQLite 初始化。
_NON_SQLITE_BYTES = b"x" * 128

# 去除首尾空白后仍有效的名称：空格与制表符只应被规整掉，随后照常访问存储。
_VALID_SURROUNDED_NAMES = [
    "  reader  ",
    "\treader\t",
    " \t reader \t ",
    "documents:read",
    "  documents:read  ",
    "\tdocuments:read\t",
    " \t documents:read \n",
]

# 空字符串与纯空白：角色、权限两个位置分别覆盖。
_BLANK_NAMES = ["", "   ", "\t", "\t \n", " \t\t "]


class RevokeNonSqliteRuleFileTests(unittest.TestCase):
    """通过 `python -m rbac revoke` 子进程核对非 SQLite 文件上的对外行为。"""

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

    def revoke(self, role, permission):
        return self.run_rbac("revoke", role, permission)

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

        标准输出为空即排除了正常业务结果 revoked=false（规则不存在时的
        成功形态）被当作存储失败替代输出的可能。
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
        # revoked=false 是合法规则库中撤销不存在授权时的正常结果，
        # 存储失败时绝不能出现。
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

    def test_precondition_file_is_exactly_128_ascii_x_without_sqlite_header(self):
        # 钉死测试输入：父目录与文件都存在，文件恰为 128 个 ASCII x，
        # 且不含 SQLite 头部，保证后续失败确实来自“内容不是数据库”。
        self.assertTrue(
            os.path.isdir(self.tmpdir), "测试前置：父目录应已存在"
        )
        self.assertTrue(
            os.path.isfile(self.db_path), "测试前置：rules.db 应已存在"
        )
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

    # ---- 名称有效时：非 SQLite 文件上的撤销存储失败 ----------------------

    def test_revoke_plain_valid_names_is_storage_error_and_preserves_bytes(self):
        snapshot = self.rule_file_bytes()

        argv = ("revoke", ROLE_READER, PERMISSION_READ)
        proc = self.run_rbac(*argv)
        self.assert_storage_error(proc, argv)
        self.assert_file_unchanged(snapshot, argv)

    def test_revoke_surrounded_valid_names_is_storage_error_and_preserves_bytes(self):
        # 角色名或权限名带首尾空格、制表符（以及混合换行），去除后仍有效：
        # 规整后照常访问存储，非 SQLite 文件同样导致存储失败。
        cases = [
            ("revoke", surrounded, PERMISSION_READ)
            for surrounded in _VALID_SURROUNDED_NAMES[:3]
        ] + [
            ("revoke", ROLE_READER, surrounded)
            for surrounded in _VALID_SURROUNDED_NAMES[3:]
        ]
        for argv in cases:
            with self.subTest(argv=argv):
                snapshot = self.rule_file_bytes()
                proc = self.run_rbac(*argv)
                self.assert_storage_error(proc, argv)
                self.assert_file_unchanged(snapshot, argv)

    def test_two_consecutive_valid_revokes_both_fail_without_changing_file(self):
        # 同一非数据库文件上连续两次有效撤销：两次独立返回存储错误，
        # 文件不能因第一次失败而被删除、截断或重新初始化。
        first_argv = ("revoke", ROLE_READER, PERMISSION_READ)
        snapshot_before_first = self.rule_file_bytes()
        first = self.run_rbac(*first_argv)
        self.assert_storage_error(first, first_argv)
        self.assert_file_unchanged(snapshot_before_first, first_argv)

        # 第二次调用前再次确认前置状态与最初完全一致。
        snapshot_before_second = self.rule_file_bytes()
        self.assertEqual(
            snapshot_before_second,
            _NON_SQLITE_BYTES,
            "第一次撤销失败后、第二次撤销前，文件应仍为最初的 128 个 x",
        )
        second_argv = ("revoke", "  reader  ", "\tdocuments:read\t")
        second = self.run_rbac(*second_argv)
        self.assert_storage_error(second, second_argv)
        self.assert_file_unchanged(snapshot_before_second, second_argv)

        # 两次调用之后文件依旧是最初的 128 个 x，两次失败互不对文件“善后”。
        self.assertEqual(
            self.rule_file_bytes(),
            _NON_SQLITE_BYTES,
            "连续两次撤销失败后，规则文件应仍为最初的 128 个 x",
        )

    # ---- 名称无效时：invalid_name 优先，不访问规则存储 -------------------

    def test_revoke_blank_role_is_invalid_and_preserves_bytes(self):
        # 角色名为空字符串或纯空白：即使文件不是数据库，也必须优先判定
        # invalid_name；权限名保持有效以隔离被测位置。
        for blank in _BLANK_NAMES:
            argv = ("revoke", blank, PERMISSION_READ)
            with self.subTest(argv=argv):
                snapshot = self.rule_file_bytes()
                proc = self.run_rbac(*argv)
                self.assert_invalid_name(proc, argv)
                # 非法名称不访问规则存储：文件字节必须原样保留。
                self.assert_file_unchanged(snapshot, argv)

    def test_revoke_blank_permission_is_invalid_and_preserves_bytes(self):
        # 权限名为空字符串或纯空白：同样优先 invalid_name，不访问存储。
        for blank in _BLANK_NAMES:
            argv = ("revoke", ROLE_READER, blank)
            with self.subTest(argv=argv):
                snapshot = self.rule_file_bytes()
                proc = self.run_rbac(*argv)
                self.assert_invalid_name(proc, argv)
                self.assert_file_unchanged(snapshot, argv)

    def test_revoke_both_blank_is_invalid_and_preserves_bytes(self):
        # 角色名与权限名同时为空/纯空白：仍是 invalid_name，文件不变。
        cases = [
            ("revoke", "", ""),
            ("revoke", "   ", "\t \n"),
            ("revoke", "\t", "   "),
        ]
        for argv in cases:
            with self.subTest(argv=argv):
                snapshot = self.rule_file_bytes()
                proc = self.run_rbac(*argv)
                self.assert_invalid_name(proc, argv)
                self.assert_file_unchanged(snapshot, argv)

    def test_invalid_name_takes_priority_over_file_content_error(self):
        # 同批输入并排对照：内容无效的文件只在名称有效时才导致 storage_error；
        # 名称一旦为空/纯空白，必须先报 invalid_name，且文件全程不被触碰。
        invalid_argv = ("revoke", "   ", PERMISSION_READ)
        valid_argv = ("revoke", ROLE_READER, PERMISSION_READ)

        snapshot = self.rule_file_bytes()
        invalid_proc = self.run_rbac(*invalid_argv)
        self.assert_invalid_name(invalid_proc, invalid_argv)
        self.assert_file_unchanged(snapshot, invalid_argv)

        # 前一次 invalid_name 不影响后续有效名称请求的存储失败判定。
        valid_proc = self.run_rbac(*valid_argv)
        self.assert_storage_error(valid_proc, valid_argv)
        self.assert_file_unchanged(snapshot, valid_argv)


if __name__ == "__main__":
    unittest.main()
