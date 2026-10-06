"""规则文件内容不是 SQLite 数据库时的命令行回归测试。

测试输入：父目录存在、已存在的 rules.db，内容固定为连续 128 个 ASCII
字符 x，未经过 SQLite 初始化。此时数据库无法打开（CREATE TABLE IF NOT
EXISTS 触发 "file is not a database"），所有调用都必须遵守既有错误协议：

- grant / list-member-permissions（含未配置成员 bob）：
  退出码 1，标准输出为空，标准错误恰为 {"error":"storage_error"} 加换行，
  不附加错误详情或异常堆栈；规则文件保持存在且全部字节不变。
  bob 虽未配置角色，也不能退化为正常的空权限汇总输出。
- 名称为空或纯空白：优先判定 invalid_name，退出码 2，标准输出为空，
  标准错误恰为 {"error":"invalid_name"} 加换行，文件内容不变。
- 对照（正常结果）：另一已存在临时目录中尚不存在的规则文件上查询 bob，
  退出码 0，标准错误为空，标准输出为
  {"member":"bob","roles":[],"permissions":[]} 加换行，并按现有行为
  初始化规则文件。

只依赖 Python 3 标准库；每个用例使用独立临时目录，结束后自动清理。
从项目根目录执行：

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

# 非 SQLite 的固定文件内容：连续 128 个 ASCII 字符 x。
NON_SQLITE_CONTENT = b"x" * 128


class NonSqliteRulefileTests(unittest.TestCase):
    """通过 `python -m rbac` 子进程核对非 SQLite 规则文件上的对外行为。"""

    def setUp(self):
        # 每个用例独立的临时目录，TemporaryDirectory.cleanup 负责清理。
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.tmpdir = self._tmpdir.name
        self.db_path = os.path.join(self.tmpdir, "rules.db")
        # 准备测试输入：父目录存在，文件已存在但内容不是 SQLite 数据库。
        with open(self.db_path, "wb") as file:
            file.write(NON_SQLITE_CONTENT)

    # ---- 辅助方法 -------------------------------------------------------

    def run_rbac(self, *argv, db_path=None):
        """运行 rbac 命令行，返回 CompletedProcess（文本模式、UTF-8）。"""
        command = [
            sys.executable,
            "-m",
            "rbac",
            "--db",
            db_path if db_path is not None else self.db_path,
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

    def read_file_bytes(self):
        """读取规则文件当前全部字节。"""
        with open(self.db_path, "rb") as file:
            return file.read()

    def assert_file_unchanged(self, content_before, context):
        """失败后规则文件应仍然存在且全部字节与调用前一致。"""
        self.assertTrue(
            os.path.isfile(self.db_path),
            f"{context}：规则文件应仍然存在：{self.db_path!r}",
        )
        self.assertEqual(
            self.read_file_bytes(),
            content_before,
            f"{context}：失败后文件内容不应变化，调用前为 {content_before!r}",
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

    # ---- 非 SQLite 文件上的业务操作 --------------------------------------

    def test_grant_non_sqlite_file_is_storage_error_and_preserves_bytes(self):
        content_before = self.read_file_bytes()
        self.assertEqual(
            content_before,
            NON_SQLITE_CONTENT,
            f"测试前置：文件内容应为 128 个 x，实际为 {content_before!r}",
        )

        argv = ("grant", "reader", PERMISSION_READ)
        proc = self.run_rbac(*argv)
        self.assert_storage_error(proc, argv)

        self.assert_file_unchanged(content_before, "grant 失败")

    def test_list_member_permissions_unconfigured_member_is_storage_error(self):
        # bob 未配置角色，但打开规则文件已失败：必须是存储错误，
        # 不得输出正常的空权限汇总 {"member":"bob","roles":[],"permissions":[]}。
        content_before = self.read_file_bytes()

        argv = ("list-member-permissions", "bob")
        proc = self.run_rbac(*argv)
        self.assert_storage_error(proc, argv)

        self.assertNotIn(
            "permissions",
            proc.stdout,
            f"输入 {argv!r}：存储失败不得输出 permissions 字段，实际为 {proc.stdout!r}",
        )
        self.assert_file_unchanged(content_before, "list-member-permissions 失败")

    # ---- 同一文件上的名称校验优先级 --------------------------------------

    def test_blank_names_are_invalid_and_preserve_bytes(self):
        content_before = self.read_file_bytes()

        cases = [
            ("grant", "", PERMISSION_READ),
            ("grant", "   ", PERMISSION_READ),
            ("grant", "reader", ""),
            ("grant", "reader", " \t\n "),
            ("list-member-permissions", ""),
            ("list-member-permissions", "  "),
        ]
        for argv in cases:
            with self.subTest(argv=argv):
                proc = self.run_rbac(*argv)
                self.assertEqual(
                    proc.returncode,
                    2,
                    f"输入 {argv!r}：期望退出码 2，实际 {proc.returncode}，"
                    f"stdout={proc.stdout!r}，stderr={proc.stderr!r}",
                )
                self.assertEqual(
                    proc.stdout,
                    "",
                    f"输入 {argv!r}：invalid_name 时标准输出应为空，"
                    f"实际为 {proc.stdout!r}",
                )
                self.assertEqual(
                    proc.stderr,
                    INVALID_NAME_ERROR,
                    f"输入 {argv!r}：标准错误应为 {INVALID_NAME_ERROR!r}，"
                    f"实际为 {proc.stderr!r}",
                )

        self.assert_file_unchanged(content_before, "非法名称调用")

    # ---- 对照：正常初始化的规则文件 --------------------------------------

    def test_missing_rulefile_unconfigured_member_returns_empty_summary(self):
        # 另一已存在的临时目录，规则文件尚不存在：按现有行为初始化并正常返回。
        with tempfile.TemporaryDirectory() as other_tmpdir:
            other_db_path = os.path.join(other_tmpdir, "rules.db")
            self.assertFalse(
                os.path.exists(other_db_path),
                f"测试前置：规则文件应尚不存在：{other_db_path!r}",
            )

            argv = ("list-member-permissions", "bob")
            proc = self.run_rbac(*argv, db_path=other_db_path)
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
            expected = {"member": "bob", "roles": [], "permissions": []}
            # 标准输出恰为单行 JSON 加一个换行。
            self.assertEqual(
                proc.stdout,
                json.dumps(expected, ensure_ascii=False, separators=(",", ":")) + "\n",
                f"输入 {argv!r}：标准输出与预期不符，实际为 {proc.stdout!r}",
            )
            self.assertEqual(
                json.loads(proc.stdout),
                expected,
                f"输入 {argv!r}：解析后的汇总结果与预期不符，实际为 {proc.stdout!r}",
            )

            # 按现有行为：规则文件已被初始化为可查询的 SQLite 数据库。
            self.assertTrue(
                os.path.isfile(other_db_path),
                f"调用后规则文件应已初始化：{other_db_path!r}",
            )
            with sqlite3.connect(other_db_path) as conn:
                rows = conn.execute(
                    "SELECT role, permission FROM role_permissions"
                ).fetchall()
            self.assertEqual(
                rows,
                [],
                f"初始化后的规则表应为空，实际为 {rows!r}",
            )


if __name__ == "__main__":
    unittest.main()
