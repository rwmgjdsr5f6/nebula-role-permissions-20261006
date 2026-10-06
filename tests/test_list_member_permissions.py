"""list-member-permissions 成员权限汇总入口的回归测试。

只依赖 Python 3 标准库；每个用例使用独立临时规则库与合成固定成员，
结束后自动清理。从项目根目录执行：

    python -m unittest discover -s tests

测试全部通过 `python -m rbac` 的公开命令行核对对外可观察行为，覆盖：
- 空规则库：alice 仍返回固定角色 reader 与空权限数组；未配置成员 bob 与
  大小写不同的 Alice 均返回空角色、空权限数组；
- alice 只汇总直接角色 reader 的授权：去重、按 Unicode 码点升序，
  不含其他角色（如 editor）的权限；
- 撤销 reader 的写权限后仅剩读权限，重新打开同一规则库结果一致；
- 成员名首尾空白被去除，输出使用规整后的名称；
- 成功查询只读：查询前后全部授权记录一致；
- 父目录存在而规则库文件尚不存在时创建可用空库并返回空权限结果；
- 成功调用退出码 0、标准错误为空、标准输出恰为一个 UTF-8 JSON 对象加
  换行，且只含 member、roles、permissions 三个字段；
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
    """通过 `python -m rbac list-member-permissions` 子进程核对对外行为。"""

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

    def parse_single_json_line(self, stdout, context):
        """标准输出必须恰好是一个 JSON 对象加一个换行；返回解析后的对象。"""
        self.assertTrue(
            stdout.endswith("\n"),
            f"{context}：标准输出应以换行结束，实际为 {stdout!r}",
        )
        self.assertEqual(
            stdout.count("\n"),
            1,
            f"{context}：标准输出应只有一个 JSON 对象加换行，实际为 {stdout!r}",
        )
        obj = json.loads(stdout[:-1])
        self.assertIsInstance(
            obj,
            dict,
            f"{context}：标准输出应为一个 JSON 对象，实际类型为 {type(obj).__name__}",
        )
        return obj

    def assert_member_permissions_success(self, proc, member):
        """成功汇总：退出码 0、stderr 为空、stdout 为只含三字段的 JSON 对象。"""
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
        result = self.parse_single_json_line(
            proc.stdout, f"输入 {argv!r}"
        )
        self.assertEqual(
            set(result.keys()),
            {"member", "roles", "permissions"},
            f"输入 {argv!r}：输出应只含 member、roles、permissions，"
            f"实际键为 {set(result.keys())}",
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
            f"输入 {argv!r}：storage_error 时标准输出应为空，实际为 {proc.stdout!r}",
        )
        self.assertEqual(
            proc.stderr,
            STORAGE_ERROR,
            f"输入 {argv!r}：标准错误应为 {STORAGE_ERROR!r}（不附加详情或堆栈），"
            f"实际为 {proc.stderr!r}",
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

    # ---- 空规则库与合成成员 ---------------------------------------------

    def test_empty_rulebase_alice_keeps_reader_role_with_empty_permissions(self):
        result = self.assert_member_permissions_success(
            self.list_member_permissions("alice"), "alice"
        )
        self.assertEqual(
            result,
            {"member": "alice", "roles": ["reader"], "permissions": []},
            f"空规则库中的 alice 应返回 reader 角色与空权限数组，实际为 {result!r}",
        )

    def test_unconfigured_members_return_empty_roles_and_permissions(self):
        # bob 与大小写不同的 Alice 都不是固定成员，均返回空角色、空权限。
        for member in ("bob", "Alice"):
            with self.subTest(member=member):
                result = self.assert_member_permissions_success(
                    self.list_member_permissions(member), member
                )
                self.assertEqual(
                    result,
                    {"member": member, "roles": [], "permissions": []},
                    f"未配置成员 {member!r} 应返回空角色与空权限，实际为 {result!r}",
                )

    def test_query_on_missing_db_creates_usable_empty_rulebase(self):
        # 父目录已存在而规则库文件尚不存在。
        self.assertFalse(os.path.exists(self.db_path), "测试前置：规则库应尚未创建")
        result = self.assert_member_permissions_success(
            self.list_member_permissions("alice"), "alice"
        )
        self.assertEqual(
            result,
            {"member": "alice", "roles": ["reader"], "permissions": []},
            f"新建空库应返回空权限结果，实际为 {result!r}",
        )
        self.assertTrue(
            os.path.exists(self.db_path),
            "父目录存在时查询应创建规则库文件",
        )

        # 新建的规则库必须可正常用于后续授权与汇总。
        self.grant("reader", PERMISSION_READ)
        reopened = self.assert_member_permissions_success(
            self.list_member_permissions("alice"), "alice"
        )
        self.assertEqual(
            reopened,
            {
                "member": "alice",
                "roles": ["reader"],
                "permissions": [PERMISSION_READ],
            },
            f"新建规则库授权后应能汇总到新权限，实际为 {reopened!r}",
        )

    # ---- reader 直接授权汇总 --------------------------------------------

    def test_alice_aggregates_only_reader_grants_sorted_and_deduped(self):
        # reader 的写、读权限；读权限重复授予一次。
        self.grant("reader", PERMISSION_WRITE)
        self.grant("reader", PERMISSION_READ)
        self.grant("reader", PERMISSION_READ)
        # editor 的权限不属于 alice 的任何直接角色，不得出现在汇总中。
        self.grant("editor", PERMISSION_EXPORT)

        result = self.assert_member_permissions_success(
            self.list_member_permissions("alice"), "alice"
        )
        self.assertEqual(
            result,
            {
                "member": "alice",
                "roles": ["reader"],
                "permissions": [PERMISSION_READ, PERMISSION_WRITE],
            },
            f"alice 应只汇总 reader 的读、写权限（去重、码点升序），"
            f"且不含 editor 的 {PERMISSION_EXPORT}，实际为 {result!r}",
        )

    def test_aggregated_permissions_sorted_by_unicode_codepoint(self):
        # Unicode 码点顺序：A < a < abc < b < 中。
        for permission in ("中", "b", "abc", "a", "A"):
            self.grant("reader", permission)

        result = self.assert_member_permissions_success(
            self.list_member_permissions("alice"), "alice"
        )
        self.assertEqual(
            result["permissions"],
            ["A", "a", "abc", "b", "中"],
            f"汇总权限应按 Unicode 码点升序排列，实际为 {result['permissions']!r}",
        )

    def test_revoke_reader_write_leaves_only_read_and_persists(self):
        self.grant("reader", PERMISSION_WRITE)
        self.grant("reader", PERMISSION_READ)
        self.grant("editor", PERMISSION_EXPORT)

        self.revoke("reader", PERMISSION_WRITE)

        expected = {
            "member": "alice",
            "roles": ["reader"],
            "permissions": [PERMISSION_READ],
        }
        result = self.assert_member_permissions_success(
            self.list_member_permissions("alice"), "alice"
        )
        self.assertEqual(
            result,
            expected,
            f"撤销写权限后应仅剩读权限且不含其他角色权限，实际为 {result!r}",
        )

        # 每次调用都是重新打开同一规则库：结果必须一致。
        reopened = self.assert_member_permissions_success(
            self.list_member_permissions("alice"), "alice"
        )
        self.assertEqual(
            reopened,
            expected,
            f"重新打开同一规则库后结果应一致，实际为 {reopened!r}",
        )

    def test_member_name_surrounding_whitespace_is_trimmed(self):
        self.grant("reader", PERMISSION_READ)

        # 带首尾空白的成员名规整为 alice，输出使用规整后的名称。
        result = self.assert_member_permissions_success(
            self.list_member_permissions("\t alice\n"), "alice"
        )
        self.assertEqual(
            result,
            {
                "member": "alice",
                "roles": ["reader"],
                "permissions": [PERMISSION_READ],
            },
            f"成员名首尾空白应被去除并按规整名称汇总，实际为 {result!r}",
        )

    def test_list_member_permissions_is_read_only(self):
        self.grant("reader", PERMISSION_READ)
        self.grant("reader", PERMISSION_WRITE)
        self.grant("editor", PERMISSION_EXPORT)
        rules_before = self.stored_rules()

        for member in ("alice", "bob", "Alice", "  alice\t"):
            self.assert_member_permissions_success(
                self.list_member_permissions(member), member
            )

        self.assertEqual(
            rules_before,
            self.stored_rules(),
            f"正常查询前后全部授权记录应一致，查询前 {rules_before!r}，"
            f"查询后 {self.stored_rules()!r}",
        )

    # ---- 错误边界 -------------------------------------------------------

    def test_empty_or_blank_member_is_invalid_and_creates_no_database(self):
        for index, member in enumerate(("", "   ", "\t \n")):
            with self.subTest(member=member):
                fresh_db = os.path.join(self.tmpdir, f"member_invalid_{index}.db")
                argv = ("list-member-permissions", member)
                proc = self.run_rbac(*argv, db=fresh_db)
                self.assert_invalid_name(proc, argv, fresh_db_path=fresh_db)

    def test_invalid_member_name_does_not_change_existing_grants(self):
        self.grant("reader", PERMISSION_READ)
        self.grant("editor", PERMISSION_EXPORT)
        rules_before = self.stored_rules()

        for member in ("", "   ", "\t\n"):
            with self.subTest(member=member):
                argv = ("list-member-permissions", member)
                self.assert_invalid_name(self.run_rbac(*argv), argv)

        self.assertEqual(
            rules_before,
            self.stored_rules(),
            f"非法名称查询不应改变已有授权，之前 {rules_before!r}，"
            f"之后 {self.stored_rules()!r}",
        )

    def test_missing_parent_directory_is_storage_error(self):
        missing_parent_db = os.path.join(self.tmpdir, "missing_dir", "rules.db")
        self.assertFalse(
            os.path.exists(os.path.dirname(missing_parent_db)),
            "测试前置：父目录应不存在",
        )
        argv = ("list-member-permissions", "alice")
        proc = self.run_rbac(*argv, db=missing_parent_db)
        self.assert_storage_error(proc, argv)
        # 精确匹配 stderr 已排除异常堆栈；规则库文件不应被创建。
        self.assertFalse(
            os.path.exists(missing_parent_db),
            f"存储失败不应创建规则库文件，实际存在 {missing_parent_db}",
        )

    def test_invalid_name_takes_precedence_over_missing_parent_directory(self):
        # 即使父目录不存在，空名称也应优先判定 invalid_name 而非 storage_error。
        missing_parent_db = os.path.join(self.tmpdir, "missing_dir", "rules.db")
        argv = ("list-member-permissions", " ")
        proc = self.run_rbac(*argv, db=missing_parent_db)
        self.assert_invalid_name(proc, argv, fresh_db_path=missing_parent_db)


if __name__ == "__main__":
    unittest.main()
