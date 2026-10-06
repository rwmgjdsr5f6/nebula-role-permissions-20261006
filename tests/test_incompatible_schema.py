"""规则表结构不兼容（缺少 permission 列）时的命令行回归测试。

测试输入：父目录存在、可正常打开的 SQLite 文件，其中 role_permissions 表
只有 role 列并保存一行 reader，缺少业务所需的 permission 列。此时数据库
能够打开（CREATE TABLE IF NOT EXISTS 对已有表为空操作），但所有需要
permission 列的业务操作都必须遵守既有错误协议：

- grant / revoke / check（已配置成员）/ list-permissions：
  退出码 1，标准输出为空，标准错误恰为 {"error":"storage_error"} 加换行，
  不附加错误详情或异常堆栈；失败后表结构与 reader 数据保持不变。
  该存储失败必须与正常业务结果明确区分：不接受成功授权、未授予、
  revoked 为 false 或空权限数组作为替代。
- check 未配置成员（bob）：不触碰规则表查询，仍按成员未配置正常返回，
  退出码 0，缺列不改变此结果。
- 名称为空或纯空白：优先判定 invalid_name，退出码 2，数据库内容不变。

只依赖 Python 3 标准库与 SQLite；每个用例使用独立临时目录，结束后自动清理。
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

# 不兼容的表结构：只有 role 列，缺少 permission 列。
_INCOMPATIBLE_SCHEMA = "CREATE TABLE role_permissions (role TEXT)"


class IncompatibleSchemaTests(unittest.TestCase):
    """通过 `python -m rbac` 子进程核对结构不兼容规则库上的对外行为。"""

    def setUp(self):
        # 每个用例独立的临时目录，TemporaryDirectory.cleanup 负责清理。
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.tmpdir = self._tmpdir.name
        self.db_path = os.path.join(self.tmpdir, "rules.db")
        # 准备测试输入：父目录存在，表只有 role 列并保存一行 reader。
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(_INCOMPATIBLE_SCHEMA)
            conn.execute("INSERT INTO role_permissions (role) VALUES ('reader')")

    # ---- 辅助方法 -------------------------------------------------------

    def run_rbac(self, *argv):
        """运行 rbac 命令行，返回 CompletedProcess（文本模式、UTF-8）。"""
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

    def stored_state(self):
        """直接读取 SQLite，返回 (建表语句, 排序后的全部行)。"""
        with sqlite3.connect(self.db_path) as conn:
            schema = conn.execute(
                "SELECT sql FROM sqlite_master WHERE name = 'role_permissions'"
            ).fetchone()[0]
            rows = sorted(conn.execute("SELECT role FROM role_permissions").fetchall())
        return schema, rows

    def assert_state_unchanged(self, state_before, context):
        """失败后表结构与 reader 数据应与调用前一致。"""
        self.assertEqual(
            self.stored_state(),
            state_before,
            f"{context}：失败后表结构与数据不应变化，调用前为 {state_before!r}",
        )

    def assert_storage_error(self, proc, argv):
        """存储失败：退出码 1，stdout 为空，stderr 仅为固定错误行。

        标准输出为空即排除了任何正常业务结果（成功授权、未授予、
        revoked 为 false、空权限数组）被当作替代输出的可能。
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

    # ---- 结构不兼容时的业务操作 ------------------------------------------

    def test_grant_incompatible_schema_is_storage_error_and_preserves_data(self):
        state_before = self.stored_state()
        self.assertEqual(
            state_before,
            (_INCOMPATIBLE_SCHEMA, [("reader",)]),
            f"测试前置：表应只有 role 列并保存一行 reader，实际为 {state_before!r}",
        )

        argv = ("grant", "reader", PERMISSION_READ)
        proc = self.run_rbac(*argv)
        self.assert_storage_error(proc, argv)

        self.assert_state_unchanged(state_before, "grant 失败")

    def test_revoke_incompatible_schema_is_storage_error_and_preserves_data(self):
        state_before = self.stored_state()

        argv = ("revoke", "reader", PERMISSION_READ)
        proc = self.run_rbac(*argv)
        self.assert_storage_error(proc, argv)

        # revoked=false 是正常业务结果，此处不得出现：标准输出必须为空。
        self.assertNotIn(
            "revoked",
            proc.stdout,
            f"输入 {argv!r}：存储失败不得输出 revoked 字段，实际为 {proc.stdout!r}",
        )
        self.assert_state_unchanged(state_before, "revoke 失败")

    def test_check_configured_member_incompatible_schema_is_storage_error(self):
        state_before = self.stored_state()

        argv = ("check", "alice", PERMISSION_READ)
        proc = self.run_rbac(*argv)
        self.assert_storage_error(proc, argv)

        # alice 已配置角色，判定必须查询规则表；缺列时是存储失败，
        # 不得退化为 allowed=true/false 的正常判定结果。
        self.assertNotIn(
            "allowed",
            proc.stdout,
            f"输入 {argv!r}：存储失败不得输出 allowed 字段，实际为 {proc.stdout!r}",
        )
        self.assert_state_unchanged(state_before, "check 失败")

    def test_list_permissions_incompatible_schema_is_storage_error(self):
        state_before = self.stored_state()

        argv = ("list-permissions", "reader")
        proc = self.run_rbac(*argv)
        self.assert_storage_error(proc, argv)

        # 空权限数组是正常业务结果，此处不得作为替代输出。
        self.assertNotIn(
            "permissions",
            proc.stdout,
            f"输入 {argv!r}：存储失败不得输出 permissions 字段，实际为 {proc.stdout!r}",
        )
        self.assert_state_unchanged(state_before, "list-permissions 失败")

    # ---- 同一输入上的边界行为 --------------------------------------------

    def test_check_unconfigured_member_is_unaffected_by_missing_column(self):
        # bob 不在固定成员配置中：判定不触碰规则表，缺列不能改变此结果。
        state_before = self.stored_state()

        argv = ("check", "bob", PERMISSION_READ)
        proc = self.run_rbac(*argv)
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
        expected = {
            "member": "bob",
            "permission": PERMISSION_READ,
            "roles": [],
            "allowed": False,
            "reason": "成员未配置",
        }
        # 标准输出恰为单行 JSON 加一个换行。
        self.assertEqual(
            proc.stdout,
            json.dumps(expected, ensure_ascii=False, separators=(",", ":")) + "\n",
            f"输入 {argv!r}：标准输出与预期不符，实际为 {proc.stdout!r}",
        )
        self.assertEqual(
            json.loads(proc.stdout),
            expected,
            f"输入 {argv!r}：解析后的判定结果与预期不符，实际为 {proc.stdout!r}",
        )

        self.assert_state_unchanged(state_before, "check 未配置成员")

    def test_blank_names_are_invalid_and_preserve_data(self):
        state_before = self.stored_state()

        cases = [
            ("grant", "", PERMISSION_READ),
            ("grant", "reader", "   "),
            ("revoke", "  ", PERMISSION_READ),
            ("revoke", "reader", "\t \n"),
            ("check", "", PERMISSION_READ),
            ("check", "alice", " "),
            ("list-permissions", ""),
            ("list-permissions", " \t\n "),
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

        self.assert_state_unchanged(state_before, "非法名称调用")


if __name__ == "__main__":
    unittest.main()
