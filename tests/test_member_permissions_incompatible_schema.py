"""list-member-permissions 在缺列规则库上的命令行回归测试。

测试输入：父目录存在、可正常打开的 SQLite 文件，其中 role_permissions 表
只有 role 列并保存一行 reader，缺少业务所需的 permission 列。此时数据库
能够打开（CREATE TABLE IF NOT EXISTS 对已有表为空操作），成员权限汇总入口
必须遵守既有错误协议，并明确区分“存储失败”与“正常空结果”：

- alice（固定对应 reader，含规整后为 alice 的带空白名称）：汇总必须查询
  规则表，缺列导致存储失败——退出码 1，标准输出为空，标准错误恰为
  {"error":"storage_error"} 加换行，不附加异常堆栈，也不得以空权限数组
  （{"member":...,"permissions":[]}）作为替代；
- bob（未配置成员）：角色列表为空，list_permissions_for_roles 直接返回
  空列表而不触碰规则表，缺列不影响此结果——退出码 0，标准错误为空，
  标准输出恰为 {"member":"bob","roles":[],"permissions":[]} 加换行，
  使用既有紧凑 UTF-8 JSON 形态；
- 成员名为空或纯空白：即使规则库缺列也优先判定 invalid_name，退出码 2，
  stdout 为空，stderr 恰为 {"error":"invalid_name"} 加换行。

每次调用后都核对表的列定义（不得新增 permission 列）与 reader 行
（不得删除或补写记录）与调用前完全一致。每个用例使用独立临时规则库，
结束后自动清理。从项目根目录执行：

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

STORAGE_ERROR = '{"error":"storage_error"}\n'
INVALID_NAME_ERROR = '{"error":"invalid_name"}\n'
BOB_EMPTY_SUMMARY = '{"member":"bob","roles":[],"permissions":[]}\n'

# 不兼容的表结构：只有 role 列，缺少 permission 列。
_INCOMPATIBLE_SCHEMA = "CREATE TABLE role_permissions (role TEXT)"


class ListMemberPermissionsIncompatibleSchemaTests(unittest.TestCase):
    """通过 `python -m rbac` 子进程核对缺列规则库上的成员权限汇总行为。"""

    def setUp(self):
        # 每个用例独立的临时规则库，TemporaryDirectory.cleanup 负责清理。
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.tmpdir = self._tmpdir.name
        self.db_path = os.path.join(self.tmpdir, "rules.db")
        # 准备测试输入：父目录存在，表只有 role 列并保存一行 reader。
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(_INCOMPATIBLE_SCHEMA)
            conn.execute("INSERT INTO role_permissions (role) VALUES ('reader')")

    # ---- 辅助方法 -------------------------------------------------------

    def run_rbac(self, member):
        """运行 list-member-permissions，返回 CompletedProcess（UTF-8 文本）。"""
        command = [
            sys.executable,
            "-m",
            "rbac",
            "--db",
            self.db_path,
            "list-member-permissions",
            member,
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
        """直接读取 SQLite，返回 (建表语句, 列定义, 排序后的全部行)。"""
        with sqlite3.connect(self.db_path) as conn:
            schema = conn.execute(
                "SELECT sql FROM sqlite_master WHERE name = 'role_permissions'"
            ).fetchone()[0]
            columns = conn.execute("PRAGMA table_info(role_permissions)").fetchall()
            rows = sorted(conn.execute("SELECT role FROM role_permissions").fetchall())
        return schema, columns, rows

    def assert_state_unchanged(self, state_before, member):
        """调用后列定义与 reader 数据应与调用前一致：不补列、不改记录。"""
        state_after = self.stored_state()
        self.assertEqual(
            state_after,
            state_before,
            f"输入 list-member-permissions {member!r}：调用后表结构或数据发生变化，"
            f"调用前为 {state_before!r}，调用后为 {state_after!r}",
        )
        # 显式钉死：列定义里不得新增 permission 列。
        column_names = [column[1] for column in state_after[1]]
        self.assertEqual(
            column_names,
            ["role"],
            f"输入 list-member-permissions {member!r}：列定义应仍只有 role，"
            f"实际为 {column_names!r}",
        )
        # 显式钉死：reader 行既不被删除，也不被补写。
        self.assertEqual(
            state_after[2],
            [("reader",)],
            f"输入 list-member-permissions {member!r}：reader 数据应保持不变，"
            f"实际为 {state_after[2]!r}",
        )

    def assert_storage_error(self, proc, member):
        """存储失败：退出码 1，stdout 为空，stderr 仅为固定错误行。

        标准输出为空即排除了以空权限数组等正常汇总结果替代失败的可能。
        """
        argv = ("list-member-permissions", member)
        self.assertEqual(
            proc.returncode,
            1,
            f"输入 {argv!r}：期望退出码 1，实际 {proc.returncode}，"
            f"stdout={proc.stdout!r}，stderr={proc.stderr!r}",
        )
        self.assertEqual(
            proc.stdout,
            "",
            f"输入 {argv!r}：storage_error 时标准输出应为空"
            f"（不得以空权限数组等成功结果替代失败），实际为 {proc.stdout!r}",
        )
        self.assertEqual(
            proc.stderr,
            STORAGE_ERROR,
            f"输入 {argv!r}：标准错误应恰为 {STORAGE_ERROR!r}"
            f"（不附加详情或堆栈），实际为 {proc.stderr!r}",
        )
        # 不得夹带异常堆栈。
        self.assertNotIn(
            "Traceback",
            proc.stderr,
            f"输入 {argv!r}：标准错误不得包含异常堆栈，实际为 {proc.stderr!r}",
        )
        # 缺列是失败而不是“没有权限”：stdout 不得是成员汇总 JSON。
        self.assertNotIn(
            "permissions",
            proc.stdout,
            f"输入 {argv!r}：存储失败不得输出 permissions 字段"
            f"（不能把查询失败当作没有权限），实际为 {proc.stdout!r}",
        )
        self.assertNotIn(
            "member",
            proc.stdout,
            f"输入 {argv!r}：存储失败不得输出成员汇总，实际为 {proc.stdout!r}",
        )

    def assert_bob_empty_success(self, proc, member):
        """未配置成员 bob：缺列不影响正常空结果，退出码 0 且输出固定。"""
        argv = ("list-member-permissions", member)
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
        result = json.loads(proc.stdout)
        self.assertEqual(
            result,
            {"member": "bob", "roles": [], "permissions": []},
            f"输入 {argv!r}：解析后的汇总与预期不符，实际为 {result!r}",
        )

    def assert_invalid_name(self, proc, member):
        """空名称/纯空白：退出码 2，stdout 为空，stderr 仅为固定错误行。"""
        argv = ("list-member-permissions", member)
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
            f"（缺列也应优先报告名称错误），实际为 {proc.stderr!r}",
        )

    # ---- 存储失败与正常空结果的区分 --------------------------------------

    def test_alice_missing_permission_column_is_storage_error(self):
        # alice 固定对应 reader：汇总必须查询 permission 列，缺列即存储失败，
        # 不得返回空权限数组把失败伪装成“没有权限”。
        state_before = self.stored_state()
        self.assertEqual(
            state_before,
            (_INCOMPATIBLE_SCHEMA, [(0, "role", "TEXT", 0, None, 0)], [("reader",)]),
            f"测试前置：表应只有 role 列并保存一行 reader，实际为 {state_before!r}",
        )

        proc = self.run_rbac("alice")
        self.assert_storage_error(proc, "alice")
        self.assert_state_unchanged(state_before, "alice")

    def test_whitespace_padded_alice_normalized_then_storage_error(self):
        # 带首尾空白但规整后为 alice：规整照常进行，随后同样命中缺列失败，
        # 输出中不得出现规整后的成功汇总。
        state_before = self.stored_state()

        proc = self.run_rbac("  alice \t\n")
        self.assert_storage_error(proc, "  alice \t\n")
        self.assertNotIn(
            "alice",
            proc.stdout,
            "存储失败时标准输出不应包含成员名，"
            f"实际为 {proc.stdout!r}",
        )
        self.assert_state_unchanged(state_before, "  alice \t\n")

    def test_bob_returns_empty_summary_despite_missing_column(self):
        # bob 未配置：角色为空，汇总不查询规则表，缺列不能把正常空结果
        # 变成失败，也不能把 alice 的存储失败泛化为“一律失败”。
        state_before = self.stored_state()

        proc = self.run_rbac("bob")
        self.assert_bob_empty_success(proc, "bob")
        self.assert_state_unchanged(state_before, "bob")

    def test_storage_error_and_empty_success_are_distinguished_on_same_db(self):
        # 同一缺列规则库上连续调用：alice 失败而 bob 成功，两种结果必须
        # 可明确区分，且互相不影响表结构与数据。
        state_before = self.stored_state()

        alice_proc = self.run_rbac("alice")
        self.assert_storage_error(alice_proc, "alice")
        self.assert_state_unchanged(state_before, "alice")

        bob_proc = self.run_rbac("bob")
        self.assert_bob_empty_success(bob_proc, "bob")
        self.assert_state_unchanged(state_before, "bob")

        # 再次查询 alice 仍应失败：bob 的成功调用不修复任何东西。
        alice_again = self.run_rbac("alice")
        self.assert_storage_error(alice_again, "alice")
        self.assert_state_unchanged(state_before, "alice")

        # 两种输出必须互不相同：一个为空 stdout 配 stderr 错误行，
        # 一个为成功 JSON 配空 stderr。
        self.assertNotEqual(
            alice_proc.stdout,
            bob_proc.stdout,
            f"alice 失败与 bob 成功的标准输出不应相同：{alice_proc.stdout!r}",
        )
        self.assertNotEqual(
            alice_proc.returncode,
            bob_proc.returncode,
            "alice 失败（退出码 1）与 bob 成功（退出码 0）必须可区分",
        )

    # ---- 名称错误优先于缺列 ----------------------------------------------

    def test_blank_member_reports_invalid_name_even_with_missing_column(self):
        # 即使规则库缺列，空字符串或纯空白成员名也必须优先报告名称错误，
        # 不打开存储语义上的业务查询，表结构与 reader 数据保持不变。
        state_before = self.stored_state()

        for member in ("", "   ", "\t \n"):
            with self.subTest(member=member):
                proc = self.run_rbac(member)
                self.assert_invalid_name(proc, member)
                # 每次调用后都核对：不补 permission 列、不改 reader 行。
                self.assert_state_unchanged(state_before, member)


if __name__ == "__main__":
    unittest.main()
