"""list-member-permissions 成员权限汇总入口的回归测试。

只依赖 Python 3 标准库；每个用例使用独立临时数据库目录，结束后自动清理。
从项目根目录执行：

    python -m unittest discover -s tests

通过 `python -m rbac` 子进程走完整公开命令行入口，覆盖范围：
- alice 只汇总其直接角色 reader 的授权：其他角色（editor）的权限不计入，
  重复授予去重，权限按 Unicode 码点升序排列，输出仅含
  member、roles、permissions 三个字段；
- 撤销 reader 的权限后汇总即时收窄，重新打开同一规则库结果一致；
- 空规则库：alice 仍返回 reader 角色与空权限数组，未配置成员 bob 与
  大小写不同的 Alice 均返回空角色、空权限数组；
- 成员名首尾空白被去除，输出使用规整后的名称；查询只读，调用前后
  全部授权记录一致；
- 父目录存在而规则库文件尚不存在时查询会创建可用空库并返回空权限结果；
- 成员名为空或纯空白：退出码 2，stdout 为空，stderr 恰为
  {"error":"invalid_name"} 加换行，不建库、不改已有授权，且即使父目录
  不存在也优先得到此结果；
- 名称有效但父目录不存在：退出码 1，stdout 为空，stderr 恰为
  {"error":"storage_error"} 加换行，不输出成功结果或异常堆栈。
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
PERMISSION_WRITE = "documents:write"
PERMISSION_EXPORT = "documents:export"
INVALID_NAME_ERROR = '{"error":"invalid_name"}\n'
STORAGE_ERROR = '{"error":"storage_error"}\n'


class ListMemberPermissionsTests(unittest.TestCase):
    """通过 `python -m rbac` 子进程核对成员权限汇总入口的对外行为。"""

    def setUp(self):
        # 每个用例独立的临时目录，TemporaryDirectory.cleanup 负责清理。
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.tmpdir = self._tmpdir.name
        self.db_path = os.path.join(self.tmpdir, "rules.db")

    # ---- 辅助方法 -------------------------------------------------------

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

    def grant(self, role, permission, **kwargs):
        return self.run_rbac("grant", role, permission, **kwargs)

    def revoke(self, role, permission, **kwargs):
        return self.run_rbac("revoke", role, permission, **kwargs)

    def list_member_permissions(self, member, **kwargs):
        return self.run_rbac("list-member-permissions", member, **kwargs)

    def assert_success_member_summary(self, proc, member):
        """成功查询：退出码 0、stderr 为空，stdout 恰为成员汇总 JSON 加换行。

        返回解析后的对象，并核对输出只含 member、roles、permissions 三个字段。
        """
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
        # 标准输出必须恰为一个 JSON 对象加一个换行，不得夹带其他输出。
        self.assertTrue(
            proc.stdout.endswith("\n"),
            f"输入 {argv!r}：标准输出应以换行结束，实际为 {proc.stdout!r}",
        )
        self.assertEqual(
            proc.stdout.count("\n"),
            1,
            f"输入 {argv!r}：标准输出应只有一个 JSON 对象加换行，"
            f"实际为 {proc.stdout!r}",
        )
        result = json.loads(proc.stdout[:-1])
        self.assertIsInstance(
            result,
            dict,
            f"输入 {argv!r}：标准输出应为一个 JSON 对象，"
            f"实际类型为 {type(result).__name__}",
        )
        self.assertEqual(
            set(result.keys()),
            {"member", "roles", "permissions"},
            f"输入 {argv!r}：输出应只含 member、roles、permissions 三个字段，"
            f"实际键为 {set(result.keys())}",
        )
        return result

    def assert_summary_equals(self, proc, member, expected_roles, expected_permissions):
        """核对一次成功汇总的完整结果（含标准输出字节形态）。"""
        result = self.assert_success_member_summary(proc, member)
        expected = {
            "member": member.strip(),
            "roles": expected_roles,
            "permissions": expected_permissions,
        }
        self.assertEqual(
            result,
            expected,
            f"输入 list-member-permissions {member!r}：期望 {expected!r}，"
            f"实际为 {result!r}",
        )
        # 紧凑 UTF-8 JSON：确保对外字节形态恰为一个对象加换行。
        expected_stdout = (
            json.dumps(expected, ensure_ascii=False, separators=(",", ":")) + "\n"
        )
        self.assertEqual(
            proc.stdout,
            expected_stdout,
            f"输入 list-member-permissions {member!r}：标准输出字节形态与预期不符，"
            f"期望 {expected_stdout!r}，实际为 {proc.stdout!r}",
        )
        return result

    def assert_invalid_name(self, proc, argv, fresh_db_path=None):
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
            f"输入 {argv!r}：标准错误应为 {INVALID_NAME_ERROR!r}，"
            f"实际为 {proc.stderr!r}",
        )
        if fresh_db_path is not None:
            self.assertFalse(
                os.path.exists(fresh_db_path),
                f"输入 {argv!r}：空名称不应创建数据库文件 {fresh_db_path}",
            )

    def assert_storage_error(self, proc, argv):
        """存储失败：退出码 1，stdout 为空，stderr 仅为固定错误行。"""
        self.assertEqual(
            proc.returncode,
            1,
            f"输入 {argv!r}：期望退出码 1，实际 {proc.returncode}，"
            f"stdout={proc.stdout!r}，stderr={proc.stderr!r}",
        )
        self.assertEqual(
            proc.stdout,
            "",
            f"输入 {argv!r}：storage_error 时标准输出应为空（不得夹带成功结果），"
            f"实际为 {proc.stdout!r}",
        )
        self.assertEqual(
            proc.stderr,
            STORAGE_ERROR,
            f"输入 {argv!r}：标准错误应恰为 {STORAGE_ERROR!r}"
            f"（不附加详情或堆栈），实际为 {proc.stderr!r}",
        )

    def stored_rules(self, db_path=None):
        """直接读取 SQLite，返回排序后的 (role, permission) 授权记录。"""
        path = self.db_path if db_path is None else db_path
        with sqlite3.connect(path) as conn:
            return sorted(
                conn.execute(
                    "SELECT role, permission FROM role_permissions"
                ).fetchall()
            )

    # ---- 汇总主流程 -----------------------------------------------------

    def test_alice_aggregates_only_reader_direct_grants_deduped_and_sorted(self):
        # reader 同时获得读、写权限；读权限重复授予。
        self.grant("reader", PERMISSION_WRITE).check_returncode()
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("reader", PERMISSION_READ).check_returncode()
        # editor 的授权与 alice（仅 reader）无关，不得出现在汇总中。
        self.grant("editor", PERMISSION_EXPORT).check_returncode()

        proc = self.list_member_permissions("alice")
        result = self.assert_summary_equals(
            proc, "alice", ["reader"], [PERMISSION_READ, PERMISSION_WRITE]
        )

        # 重复授予不得产生重复项；其他角色的权限不得计入。
        self.assertEqual(
            len(result["permissions"]),
            len(set(result["permissions"])),
            f"权限数组应无重复项，实际为 {result['permissions']!r}",
        )
        self.assertNotIn(
            PERMISSION_EXPORT,
            result["permissions"],
            f"alice 只有 reader 角色，不应包含 editor 的权限，"
            f"实际为 {result['permissions']!r}",
        )
        # 码点升序：documents:read < documents:write。
        self.assertEqual(
            result["permissions"],
            sorted(result["permissions"]),
            f"权限应按 Unicode 码点升序排列，实际为 {result['permissions']!r}",
        )

        # 授权记录中确有 editor 的授权，证明“不含其他角色权限”是汇总隔离，
        # 而非授权未写入。
        self.assertEqual(
            self.stored_rules(),
            [
                ("editor", PERMISSION_EXPORT),
                ("reader", PERMISSION_READ),
                ("reader", PERMISSION_WRITE),
            ],
            f"授权记录与预置不符，实际为 {self.stored_rules()!r}",
        )

    def test_revoke_reader_write_narrows_summary_and_persists_on_reopen(self):
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("reader", PERMISSION_WRITE).check_returncode()
        self.grant("editor", PERMISSION_EXPORT).check_returncode()

        # 撤销 reader 的写权限：只影响 reader，且汇总中立即消失。
        revoke_proc = self.revoke("reader", PERMISSION_WRITE)
        self.assertEqual(
            revoke_proc.returncode,
            0,
            f"撤销准备失败：stdout={revoke_proc.stdout!r}，"
            f"stderr={revoke_proc.stderr!r}",
        )

        proc = self.list_member_permissions("alice")
        self.assert_summary_equals(
            proc, "alice", ["reader"], [PERMISSION_READ]
        )

        # 每次调用都重新打开同一规则库：撤销后的收窄结果必须持久化。
        reopened_proc = self.list_member_permissions("alice")
        reopened = self.assert_summary_equals(
            reopened_proc, "alice", ["reader"], [PERMISSION_READ]
        )
        self.assertEqual(
            reopened_proc.stdout,
            proc.stdout,
            f"重新打开同一规则库后结果应一致，首次 {proc.stdout!r}，"
            f"重开后 {reopened_proc.stdout!r}",
        )

        # editor 的授权仍然存在，只是与 alice 无关。
        self.assertEqual(
            self.stored_rules(),
            [("editor", PERMISSION_EXPORT), ("reader", PERMISSION_READ)],
            f"撤销后授权记录与预期不符，实际为 {self.stored_rules()!r}",
        )

    def test_empty_rulebase_returns_role_with_empty_permissions_for_alice(self):
        # 查询本身会建库；alice 固定拥有 reader，但尚无任何授权。
        proc = self.list_member_permissions("alice")
        self.assert_summary_equals(proc, "alice", ["reader"], [])

    def test_unconfigured_and_differently_cased_members_have_empty_roles(self):
        # bob 与大小写不同的 Alice 均不是固定成员：空角色、空权限。
        for member in ("bob", "Alice"):
            with self.subTest(member=member):
                proc = self.list_member_permissions(member)
                self.assert_summary_equals(proc, member, [], [])

    def test_member_name_surrounding_whitespace_is_trimmed(self):
        self.grant("reader", PERMISSION_READ).check_returncode()

        # 带首尾空白的成员名规整为 alice；输出使用规整后的名称。
        proc = self.list_member_permissions("\t alice \n")
        result = self.assert_success_member_summary(proc, "\t alice \n")
        self.assertEqual(
            result["member"],
            "alice",
            f"输出成员名应为规整后的 alice，实际为 {result['member']!r}",
        )
        self.assertEqual(
            result,
            {
                "member": "alice",
                "roles": ["reader"],
                "permissions": [PERMISSION_READ],
            },
            f"带空白名称的汇总结果与预期不符，实际为 {result!r}",
        )

    def test_permissions_sorted_by_unicode_codepoint(self):
        # 直接为 reader 预置码点顺序与写入顺序不同的权限，验证汇总排序。
        for permission in ("中", "a", "A", "documents:read"):
            self.grant("reader", permission).check_returncode()

        proc = self.list_member_permissions("alice")
        result = self.assert_success_member_summary(proc, "alice")
        # Unicode 码点升序：A(0x41) < a(0x61) < documents:read < 中(0x4E2D)。
        self.assertEqual(
            result["permissions"],
            ["A", "a", PERMISSION_READ, "中"],
            f"权限应按 Unicode 码点升序排列，实际为 {result['permissions']!r}",
        )

    def test_member_query_is_read_only(self):
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("reader", PERMISSION_WRITE).check_returncode()
        self.grant("editor", PERMISSION_EXPORT).check_returncode()
        rules_before = self.stored_rules()

        # 正常查询前后（含已配置、未配置、带空白成员名）全部授权记录一致。
        for member in ("alice", "bob", "Alice", "  alice\t"):
            with self.subTest(member=member):
                proc = self.list_member_permissions(member)
                self.assert_success_member_summary(proc, member)

        self.assertEqual(
            self.stored_rules(),
            rules_before,
            f"成员权限汇总应为只读：查询前 {rules_before!r}，"
            f"查询后 {self.stored_rules()!r}",
        )

    def test_missing_db_with_existing_parent_is_created_and_usable(self):
        self.assertFalse(
            os.path.exists(self.db_path), "测试前置：规则库文件应尚未创建"
        )

        # 父目录已存在而文件不存在：查询 alice 应创建可用空库并返回空权限。
        proc = self.list_member_permissions("alice")
        self.assert_summary_equals(proc, "alice", ["reader"], [])
        self.assertTrue(
            os.path.exists(self.db_path),
            "父目录存在时查询应创建规则库文件",
        )

        # 创建出的库必须可用：授权后再次查询即可看到新权限。
        self.grant("reader", PERMISSION_READ).check_returncode()
        followup = self.list_member_permissions("alice")
        self.assert_summary_equals(
            followup, "alice", ["reader"], [PERMISSION_READ]
        )

    # ---- 错误边界 -------------------------------------------------------

    def test_empty_or_blank_member_is_invalid_and_creates_no_database(self):
        for index, member in enumerate(("", "   ", "\t \n")):
            with self.subTest(member=member):
                fresh_db = os.path.join(self.tmpdir, f"member_invalid_{index}.db")
                argv = ("list-member-permissions", member)
                proc = self.run_rbac(*argv, db=fresh_db)
                self.assert_invalid_name(proc, argv, fresh_db_path=fresh_db)

    def test_invalid_member_does_not_change_existing_grants(self):
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("editor", PERMISSION_EXPORT).check_returncode()
        rules_before = self.stored_rules()

        for member in ("", "   ", "\t\n "):
            with self.subTest(member=member):
                argv = ("list-member-permissions", member)
                self.assert_invalid_name(self.run_rbac(*argv), argv)

        self.assertEqual(
            self.stored_rules(),
            rules_before,
            f"非法名称查询不应改变已有授权，之前 {rules_before!r}，"
            f"之后 {self.stored_rules()!r}",
        )

    def test_invalid_name_takes_precedence_over_missing_parent_directory(self):
        # 即使数据库父目录不存在，空名称也必须优先判定 invalid_name，
        # 且全程不触碰存储（不创建父目录或数据库文件）。
        missing_parent_db = os.path.join(self.tmpdir, "missing_dir", "rules.db")
        argv = ("list-member-permissions", " ")
        proc = self.run_rbac(*argv, db=missing_parent_db)
        self.assert_invalid_name(proc, argv, fresh_db_path=missing_parent_db)
        self.assertFalse(
            os.path.exists(os.path.dirname(missing_parent_db)),
            f"输入 {argv!r}：invalid_name 不应创建父目录，"
            f"实际存在 {os.path.dirname(missing_parent_db)!r}",
        )

    def test_valid_name_with_missing_parent_directory_is_storage_error(self):
        missing_parent_db = os.path.join(self.tmpdir, "missing_dir", "rules.db")
        self.assertFalse(
            os.path.exists(os.path.dirname(missing_parent_db)),
            "测试前置：父目录应不存在",
        )

        argv = ("list-member-permissions", "alice")
        proc = self.run_rbac(*argv, db=missing_parent_db)
        self.assert_storage_error(proc, argv)

        # 不得夹带任何成功结果或异常堆栈。
        self.assertNotIn(
            "permissions",
            proc.stdout,
            f"输入 {argv!r}：存储失败不得输出成功汇总，实际为 {proc.stdout!r}",
        )
        self.assertNotIn(
            "Traceback",
            proc.stderr,
            f"输入 {argv!r}：标准错误不得包含异常堆栈，实际为 {proc.stderr!r}",
        )


if __name__ == "__main__":
    unittest.main()
