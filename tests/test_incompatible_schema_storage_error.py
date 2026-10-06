"""规则表结构不兼容时的命令行回归测试。

与“数据库父目录不存在”不同，本类输入的前提是：

- SQLite 文件真实存在且父目录存在，数据库本身可以正常打开
  （store.connect 中的 CREATE TABLE IF NOT EXISTS 不会改动既有表）；
- role_permissions 表结构不兼容业务操作：只有 role 列、缺少
  permission 列，并预置一行 role='reader'。

此时业务读写必须在 SQL 执行阶段失败，并统一遵守既有存储错误协议：
退出码 1、标准输出为空、标准错误恰好为 {"error":"storage_error"} 加
换行，不附加错误详情或异常堆栈；失败不得修复或改动表结构与已有数据。

只依赖 Python 3 标准库；每个用例使用独立临时数据库目录，结束后自动清理。
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
INVALID_NAME_ERROR = '{"error":"invalid_name"}\n'
STORAGE_ERROR = '{"error":"storage_error"}\n'


class IncompatibleSchemaStorageErrorTests(unittest.TestCase):
    """缺列规则库上通过 `python -m rbac` 子进程核对对外可观察行为。"""

    def setUp(self):
        # 每个用例独立的临时目录，TemporaryDirectory.cleanup 负责清理。
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.tmpdir = self._tmpdir.name
        self.db_path = os.path.join(self.tmpdir, "rules.db")
        self._create_incompatible_database()

    # ---- 夹具与辅助方法 -------------------------------------------------

    def _create_incompatible_database(self):
        """创建可打开但表结构不兼容的规则库。

        role_permissions 只有 role 列并保存一行 reader，缺少业务操作
        依赖的 permission 列；父目录必然存在。
        """
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("CREATE TABLE role_permissions (role TEXT NOT NULL)")
            conn.execute(
                "INSERT INTO role_permissions (role) VALUES (?)", ("reader",)
            )
            conn.commit()
        finally:
            conn.close()

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

    def schema_snapshot(self):
        """重新打开数据库，读取列名序列与 role 数据；证明库始终可打开。

        每次都用全新连接，避免复用缓存掩盖调用后的结构变化。
        """
        self.assertTrue(
            os.path.exists(self.db_path),
            "测试前置：SQLite 文件应存在且可打开",
        )
        conn = sqlite3.connect(self.db_path)
        try:
            columns = [
                row[1]
                for row in conn.execute("PRAGMA table_info(role_permissions)")
            ]
            roles = conn.execute(
                "SELECT role FROM role_permissions ORDER BY role"
            ).fetchall()
        finally:
            conn.close()
        return columns, roles

    def assert_schema_unchanged(self, context, expected):
        """表结构（仅 role 列）与 reader 数据在调用前后保持一致。"""
        columns, roles = self.schema_snapshot()
        self.assertEqual(
            columns,
            ["role"],
            f"{context}：失败不得补列或改表，实际列为 {columns!r}",
        )
        self.assertEqual(
            roles,
            [("reader",)],
            f"{context}：已有 reader 数据不应变化，实际为 {roles!r}",
        )
        self.assertEqual(
            (columns, roles),
            expected,
            f"{context}：表结构与数据应与调用前完全一致，"
            f"调用前 {expected!r}，调用后 {(columns, roles)!r}",
        )

    def assert_storage_error_only(self, proc, argv):
        """存储失败协议：退出码 1、stdout 为空、stderr 仅为固定错误行。

        stdout 必须为空，从而排除成功授权、未授予拒绝、revoked=false、
        空权限数组等任何正常业务 JSON 被当作替代结果；stderr 不得附带
        sqlite3 错误详情或异常堆栈。
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
            f"输入 {argv!r}：storage_error 时标准输出应为空，"
            f"不能以正常业务结果代替，实际为 {proc.stdout!r}",
        )
        self.assertEqual(
            proc.stderr,
            STORAGE_ERROR,
            f"输入 {argv!r}：标准错误应恰为 {STORAGE_ERROR!r}，"
            f"不应附加错误详情或堆栈，实际为 {proc.stderr!r}",
        )

    def assert_invalid_name_only(self, proc, argv):
        """空名称/纯空白：退出码 2、stdout 为空、stderr 仅为固定错误行。"""
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
            f"输入 {argv!r}：标准错误应恰为 {INVALID_NAME_ERROR!r}，"
            f"实际为 {proc.stderr!r}",
        )

    # ---- 业务操作失败遵守存储错误协议 -----------------------------------

    def test_business_operations_fail_with_storage_error_protocol(self):
        # 前置：数据库可以打开，且表结构只有 role 列、一行 reader。
        before = self.schema_snapshot()
        self.assertEqual(
            before,
            (["role"], [("reader",)]),
            f"测试前置不符合预期，实际为 {before!r}",
        )

        cases = [
            ("grant", "reader", PERMISSION_READ),
            ("revoke", "reader", PERMISSION_READ),
            ("check", "alice", PERMISSION_READ),
            ("list-permissions", "reader"),
        ]
        for argv in cases:
            with self.subTest(argv=argv):
                proc = self.run_rbac(*argv)
                self.assert_storage_error_only(proc, argv)
                # 每次失败后都重新读取该文件：结构与数据须与调用前一致。
                self.assert_schema_unchanged(f"调用 {argv!r} 失败后", before)

    def test_each_failure_is_distinct_from_normal_business_results(self):
        """明确区分存储失败与可能被混淆的正常业务结果。

        - grant 不得返回成功授权 JSON；
        - check alice 不得返回 reason=权限未授予 的拒绝；
        - revoke 不得返回 revoked=false；
        - list-permissions 不得返回空权限数组。
        上述任何结果都必然出现在 stdout 且退出码为 0，与协议互斥；
        这里逐字段确认不会误判。
        """
        proc = self.run_rbac("grant", "reader", PERMISSION_READ)
        self.assert_storage_error_only(
            proc, ("grant", "reader", PERMISSION_READ)
        )
        self.assertNotIn(
            '"role"', proc.stdout, "grant 失败不能以成功授权输出代替"
        )

        proc = self.run_rbac("revoke", "reader", PERMISSION_READ)
        self.assert_storage_error_only(
            proc, ("revoke", "reader", PERMISSION_READ)
        )
        self.assertNotIn(
            '"revoked"', proc.stdout, "revoke 失败不能以 revoked 结果代替"
        )

        proc = self.run_rbac("check", "alice", PERMISSION_READ)
        self.assert_storage_error_only(
            proc, ("check", "alice", PERMISSION_READ)
        )
        self.assertNotIn(
            '"allowed"', proc.stdout, "check 失败不能以未授予拒绝结果代替"
        )

        proc = self.run_rbac("list-permissions", "reader")
        self.assert_storage_error_only(proc, ("list-permissions", "reader"))
        self.assertNotIn(
            '"permissions"',
            proc.stdout,
            "list-permissions 失败不能以空权限数组代替",
        )

    # ---- 同库上的直接相关边界 -------------------------------------------

    def test_check_unconfigured_member_still_succeeds(self):
        # bob 不是固定成员、角色为空：permission_granted 不会触碰数据库，
        # 缺列不能改变“成员未配置”的正常结果。
        before = self.schema_snapshot()
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
        self.assertEqual(
            proc.stdout,
            '{"member":"bob","permission":"documents:read","roles":[],"allowed":false,"reason":"成员未配置"}\n',
            f"输入 {argv!r}：标准输出与未配置成员协议不符，"
            f"实际为 {proc.stdout!r}",
        )

        # 交叉核对：输出必须是单行 JSON，以恰好一个换行结束。
        self.assertEqual(proc.stdout.count("\n"), 1)
        self.assertEqual(
            json.loads(proc.stdout[:-1]),
            {
                "member": "bob",
                "permission": PERMISSION_READ,
                "roles": [],
                "allowed": False,
                "reason": "成员未配置",
            },
        )
        # 缺列表结构与 reader 数据保持不变。
        self.assert_schema_unchanged("check bob 成功后", before)

    def test_empty_or_blank_names_take_precedence(self):
        # 名称去空白后为空时，应在打开存储之前判定 invalid_name
        # （退出码 2），缺列存储错误不得提前暴露，数据库内容不变。
        before = self.schema_snapshot()
        cases = [
            ("grant", "", PERMISSION_READ),
            ("grant", "reader", "   "),
            ("revoke", "  ", PERMISSION_READ),
            ("revoke", "reader", "\t \n"),
            ("check", "", PERMISSION_READ),
            ("check", "bob", "  "),
            ("list-permissions", "\t"),
        ]
        for argv in cases:
            with self.subTest(argv=argv):
                proc = self.run_rbac(*argv)
                self.assert_invalid_name_only(proc, argv)
                self.assert_schema_unchanged(f"输入 {argv!r} 之后", before)


if __name__ == "__main__":
    unittest.main()
