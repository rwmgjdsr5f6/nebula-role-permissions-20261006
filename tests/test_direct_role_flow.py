"""直接角色授权后查询成员权限流程的回归测试。

只依赖 Python 3 标准库；每个用例使用独立临时 SQLite 文件，结束后清理。
覆盖：空规则库查询、授予/查询、重开持久化、重复授予幂等、未授予权限与
未配置成员、名称首尾空白规整、大小写敏感完整匹配、空名称与存储失败的
错误约定（退出码与标准输出/错误内容）。

从项目根目录执行：

    python -m unittest discover -s tests
"""

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest

# 项目根目录（tests 的上一级），保证子进程能以 -m rbac 导入包。
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

INVALID_NAME_ERROR = '{"error":"invalid_name"}\n'
STORAGE_ERROR = '{"error":"storage_error"}\n'


def _compact(obj):
    """与 CLI 一致的紧凑 JSON 形态（中文不转义）。"""
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def run_cli(db_path, command, name, permission):
    """以子进程执行一条 grant/check 命令，返回 CompletedProcess。"""
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "rbac",
            "--db",
            str(db_path),
            command,
            name,
            permission,
        ],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )


def dump_grants(db_path):
    """直接读取库中全部“角色 -> 权限”记录，按字典序返回。"""
    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute(
            "SELECT role, permission FROM role_permissions"
        ).fetchall()
    finally:
        conn.close()
    return sorted(rows)


class DirectRoleFlowTest(unittest.TestCase):
    """固定成员 alice -> reader 的直接角色授权与查询。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="rbac-test-")
        self.db_path = os.path.join(self.tmpdir, "rules.db")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def assertSuccess(self, result, expected_stdout_obj, args):
        """成功调用：退出码 0、标准错误为空、标准输出为单个紧凑 JSON + 换行。"""
        expected_line = _compact(expected_stdout_obj) + "\n"
        self.assertEqual(
            result.returncode,
            0,
            "输入 %r 应成功退出，实际退出码 %r，stdout=%r stderr=%r"
            % (args, result.returncode, result.stdout, result.stderr),
        )
        self.assertEqual(
            result.stderr,
            "",
            "输入 %r 成功时标准错误应为空，实际为 %r" % (args, result.stderr),
        )
        self.assertEqual(
            result.stdout,
            expected_line,
            "输入 %r 输出与预期不符，期望 %r，实际 %r"
            % (args, expected_line, result.stdout),
        )
        # 标准输出仅含一个 JSON 对象及一个换行。
        self.assertEqual(result.stdout.count("\n"), 1)

    def test_check_on_empty_rulebase_denied(self):
        result = run_cli(self.db_path, "check", "alice", "documents:read")
        self.assertSuccess(
            result,
            {
                "member": "alice",
                "permission": "documents:read",
                "roles": ["reader"],
                "allowed": False,
                "reason": "权限未授予",
            },
            ("check", "alice", "documents:read"),
        )

    def test_grant_then_check_allowed_by_direct_role(self):
        grant_result = run_cli(
            self.db_path, "grant", "reader", "documents:read"
        )
        self.assertSuccess(
            grant_result,
            {"role": "reader", "permission": "documents:read"},
            ("grant", "reader", "documents:read"),
        )

        check_result = run_cli(
            self.db_path, "check", "alice", "documents:read"
        )
        self.assertSuccess(
            check_result,
            {
                "member": "alice",
                "permission": "documents:read",
                "roles": ["reader"],
                "allowed": True,
                "reason": "直接角色授权",
            },
            ("check", "alice", "documents:read"),
        )

    def test_grant_persists_after_reopening_database(self):
        result = run_cli(self.db_path, "grant", "reader", "documents:read")
        self.assertEqual(result.returncode, 0)

        # 每次 CLI 调用都会重新打开同一数据库文件。
        reopened = run_cli(self.db_path, "check", "alice", "documents:read")
        self.assertSuccess(
            reopened,
            {
                "member": "alice",
                "permission": "documents:read",
                "roles": ["reader"],
                "allowed": True,
                "reason": "直接角色授权",
            },
            ("reopened-check", "alice", "documents:read"),
        )
        self.assertEqual(
            dump_grants(self.db_path),
            [("reader", "documents:read")],
        )

    def test_duplicate_grant_keeps_single_record(self):
        args = ("grant", "reader", "documents:read")
        first = run_cli(self.db_path, "grant", "reader", "documents:read")
        second = run_cli(self.db_path, "grant", "reader", "documents:read")
        self.assertSuccess(
            first, {"role": "reader", "permission": "documents:read"}, args
        )
        self.assertSuccess(
            second, {"role": "reader", "permission": "documents:read"}, args
        )
        self.assertEqual(
            dump_grants(self.db_path),
            [("reader", "documents:read")],
            "重复授予后仍应只有一条记录",
        )

    def test_check_ungranted_permission_denied(self):
        run_cli(self.db_path, "grant", "reader", "documents:read")
        result = run_cli(self.db_path, "check", "alice", "documents:write")
        self.assertSuccess(
            result,
            {
                "member": "alice",
                "permission": "documents:write",
                "roles": ["reader"],
                "allowed": False,
                "reason": "权限未授予",
            },
            ("check", "alice", "documents:write"),
        )

    def test_check_unconfigured_member_denied(self):
        result = run_cli(self.db_path, "check", "bob", "documents:read")
        self.assertSuccess(
            result,
            {
                "member": "bob",
                "permission": "documents:read",
                "roles": [],
                "allowed": False,
                "reason": "成员未配置",
            },
            ("check", "bob", "documents:read"),
        )

    def test_names_trimmed_on_grant_and_check(self):
        grant_result = run_cli(
            self.db_path, "grant", "  reader  ", "\tdocuments:read "
        )
        # 返回结果使用规整后的名称。
        self.assertSuccess(
            grant_result,
            {"role": "reader", "permission": "documents:read"},
            ("grant", "  reader  ", "\\tdocuments:read "),
        )

        check_result = run_cli(
            self.db_path, "check", "  alice\n", "  documents:read  "
        )
        self.assertSuccess(
            check_result,
            {
                "member": "alice",
                "permission": "documents:read",
                "roles": ["reader"],
                "allowed": True,
                "reason": "直接角色授权",
            },
            ("check", "  alice\\n", "  documents:read  "),
        )
        self.assertEqual(
            dump_grants(self.db_path),
            [("reader", "documents:read")],
        )

    def test_member_name_matching_is_case_sensitive(self):
        run_cli(self.db_path, "grant", "reader", "documents:read")
        result = run_cli(self.db_path, "check", "Alice", "documents:read")
        # Alice 是未配置成员，不应命中 alice。
        self.assertSuccess(
            result,
            {
                "member": "Alice",
                "permission": "documents:read",
                "roles": [],
                "allowed": False,
                "reason": "成员未配置",
            },
            ("check", "Alice", "documents:read"),
        )

    def test_permission_matching_is_case_sensitive(self):
        run_cli(self.db_path, "grant", "reader", "documents:read")
        result = run_cli(self.db_path, "check", "alice", "documents:Read")
        self.assertSuccess(
            result,
            {
                "member": "alice",
                "permission": "documents:Read",
                "roles": ["reader"],
                "allowed": False,
                "reason": "权限未授予",
            },
            ("check", "alice", "documents:Read"),
        )

    def test_blank_names_rejected_without_creating_database(self):
        # 命令、第一个名称（角色/成员）、第二个名称（权限）的空值组合。
        cases = [
            ("grant", "", "documents:read"),
            ("grant", "   ", "documents:read"),
            ("grant", "\t\n", "documents:read"),
            ("grant", "reader", ""),
            ("grant", "reader", "   "),
            ("check", "", "documents:read"),
            ("check", "   ", "documents:read"),
            ("check", "alice", ""),
            ("check", "alice", "\t "),
        ]
        for command, name, permission in cases:
            with self.subTest(command=command, name=name, permission=permission):
                args = (command, name, permission)
                result = run_cli(self.db_path, command, name, permission)
                self.assertEqual(
                    result.returncode,
                    2,
                    "输入 %r 空名称应退出码 2，实际 %r，stdout=%r stderr=%r"
                    % (args, result.returncode, result.stdout, result.stderr),
                )
                self.assertEqual(
                    result.stdout,
                    "",
                    "输入 %r 失败时标准输出应为空，实际 %r"
                    % (args, result.stdout),
                )
                self.assertEqual(
                    result.stderr,
                    INVALID_NAME_ERROR,
                    "输入 %r 标准错误与预期不符，实际 %r"
                    % (args, result.stderr),
                )
                # 名称校验先于存储打开：不得创建数据库文件。
                self.assertFalse(
                    os.path.exists(self.db_path),
                    "输入 %r 为非法名称时不应创建数据库" % (args,),
                )

    def test_blank_names_do_not_change_existing_grants(self):
        run_cli(self.db_path, "grant", "reader", "documents:read")
        before = dump_grants(self.db_path)

        for command, name, permission in [
            ("grant", " ", "documents:read"),
            ("grant", "reader", "\t"),
            ("check", "", "documents:read"),
            ("check", "alice", "   "),
        ]:
            with self.subTest(command=command, name=name, permission=permission):
                result = run_cli(self.db_path, command, name, permission)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stderr, INVALID_NAME_ERROR)
                self.assertEqual(
                    dump_grants(self.db_path),
                    before,
                    "输入 (%r, %r, %r) 后授权记录被改动"
                    % (command, name, permission),
                )

    def test_missing_parent_directory_is_storage_error(self):
        missing_parent = os.path.join(self.tmpdir, "no-such-dir")
        db_path = os.path.join(missing_parent, "rules.db")
        args = ("grant", "reader", "documents:read")
        result = run_cli(db_path, "grant", "reader", "documents:read")
        self.assertEqual(
            result.returncode,
            1,
            "输入 %r 存储失败应退出码 1，实际 %r，stdout=%r stderr=%r"
            % (args, result.returncode, result.stdout, result.stderr),
        )
        self.assertEqual(
            result.stdout,
            "",
            "输入 %r 失败时标准输出应为空，实际 %r" % (args, result.stdout),
        )
        self.assertEqual(
            result.stderr,
            STORAGE_ERROR,
            "输入 %r 标准错误与预期不符，实际 %r" % (args, result.stderr),
        )
        self.assertFalse(os.path.isdir(missing_parent))

    def test_invalid_name_takes_precedence_over_storage_error(self):
        db_path = os.path.join(self.tmpdir, "no-such-dir", "rules.db")
        # 同一路径配合空名称时仍优先返回 invalid_name。
        result = run_cli(db_path, "grant", "   ", "documents:read")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, INVALID_NAME_ERROR)
        self.assertFalse(
            os.path.exists(os.path.dirname(db_path)),
            "非法名称优先时不应尝试创建存储路径",
        )

    def test_checks_do_not_change_grant_records(self):
        run_cli(self.db_path, "grant", "reader", "documents:read")
        before = dump_grants(self.db_path)

        # 允许、未授予权限、未配置成员三类查询均为只读。
        queries = [
            ("alice", "documents:read"),
            ("alice", "documents:write"),
            ("bob", "documents:read"),
        ]
        for member, permission in queries:
            with self.subTest(member=member, permission=permission):
                result = run_cli(self.db_path, "check", member, permission)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(dump_grants(self.db_path), before)


if __name__ == "__main__":
    unittest.main()
