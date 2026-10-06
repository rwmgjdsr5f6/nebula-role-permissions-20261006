"""直接角色授权后查询成员权限流程的回归测试。

只依赖 Python 3 标准库；每个用例使用独立临时数据库目录，结束后自动清理。
从项目根目录执行：

    python -m unittest discover -s tests

覆盖范围：
- 空规则库查询、授权后允许、重新打开持久化、重复授予幂等；
- 撤销已有授权返回 revoked=true、撤销后查询拒绝且持久化、重复撤销
  与不存在规则返回 revoked=false、撤销不影响其他授权、撤销后可重新授予；
- 未授予权限与未配置成员的拒绝原因；
- 成功调用的退出码 0、标准输出单个 JSON 对象加换行、标准错误为空；
- 查询前后授权记录一致（查询只读）；
- 名称首尾空白规整、大小写敏感的完整字符串匹配；
- 空名称/纯空白名称返回 invalid_name（退出码 2），不建库、不改已有授权；
- 数据库父目录不存在返回 storage_error（退出码 1），且空名称优先判定。
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
INVALID_NAME_ERROR = '{"error":"invalid_name"}\n'
STORAGE_ERROR = '{"error":"storage_error"}\n'


class DirectRoleFlowTests(unittest.TestCase):
    """通过 `python -m rbac` 子进程走完整公开入口，核对对外可观察行为。"""

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

    def check(self, member, permission, **kwargs):
        return self.run_rbac("check", member, permission, **kwargs)

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

    def assert_success_json(self, proc, context):
        """成功调用：退出码 0、标准错误为空、标准输出为单个 JSON 对象。"""
        self.assertEqual(
            proc.returncode,
            0,
            f"{context}：期望退出码 0，实际 {proc.returncode}，"
            f"stdout={proc.stdout!r}，stderr={proc.stderr!r}",
        )
        self.assertEqual(
            proc.stderr,
            "",
            f"{context}：成功时标准错误应为空，实际为 {proc.stderr!r}",
        )
        return self.parse_single_json_line(proc.stdout, context)

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
            f"输入 {argv!r}：标准错误应为 {STORAGE_ERROR!r}，实际为 {proc.stderr!r}",
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

    # ---- 主流程 ---------------------------------------------------------

    def test_check_on_empty_rulebase_is_denied_as_not_granted(self):
        result = self.assert_success_json(
            self.check("alice", PERMISSION_READ), "空规则库查询 alice/documents:read"
        )
        self.assertEqual(
            result,
            {
                "member": "alice",
                "permission": PERMISSION_READ,
                "roles": ["reader"],
                "allowed": False,
                "reason": "权限未授予",
            },
            f"空规则库查询结果与预期不符，输入为 alice/{PERMISSION_READ}，实际为 {result!r}",
        )

    def test_grant_then_check_allowed_persisted_and_idempotent(self):
        grant_result = self.assert_success_json(
            self.grant("reader", PERMISSION_READ), "授予 reader/documents:read"
        )
        self.assertEqual(
            grant_result,
            {"role": "reader", "permission": PERMISSION_READ},
            f"grant 返回内容与预期不符，实际为 {grant_result!r}",
        )

        # check 返回正确成员与权限，允许原因为“直接角色授权”。
        check_result = self.assert_success_json(
            self.check("alice", PERMISSION_READ), "授权后查询 alice/documents:read"
        )
        self.assertEqual(
            check_result,
            {
                "member": "alice",
                "permission": PERMISSION_READ,
                "roles": ["reader"],
                "allowed": True,
                "reason": "直接角色授权",
            },
            f"授权后查询结果与预期不符，实际为 {check_result!r}",
        )

        # 每次调用都是重新打开同一数据库文件：授权必须持久化。
        reopened_result = self.assert_success_json(
            self.check("alice", PERMISSION_READ), "重新打开数据库后再次查询"
        )
        self.assertEqual(
            reopened_result,
            check_result,
            f"重新打开数据库后结果发生变化，实际为 {reopened_result!r}",
        )

        # 重复授予同一规则：表里仍只有一条记录，且继续允许。
        self.assert_success_json(
            self.grant("reader", PERMISSION_READ), "重复授予 reader/documents:read"
        )
        rules = self.stored_rules()
        self.assertEqual(
            rules,
            [("reader", PERMISSION_READ)],
            f"重复授予后授权记录应仍只有一条，实际为 {rules!r}",
        )

    def test_check_ungranted_permission_is_denied_as_not_granted(self):
        # 先授予 read，再查询未授予的 write。
        self.assert_success_json(
            self.grant("reader", PERMISSION_READ), "授予 reader/documents:read"
        )
        result = self.assert_success_json(
            self.check("alice", PERMISSION_WRITE), "查询未授予的 documents:write"
        )
        self.assertEqual(
            result,
            {
                "member": "alice",
                "permission": PERMISSION_WRITE,
                "roles": ["reader"],
                "allowed": False,
                "reason": "权限未授予",
            },
            f"未授予权限的查询结果与预期不符，输入为 alice/{PERMISSION_WRITE}，"
            f"实际为 {result!r}",
        )

    def test_check_unconfigured_member_has_empty_roles(self):
        result = self.assert_success_json(
            self.check("bob", PERMISSION_READ), "查询未配置成员 bob"
        )
        self.assertEqual(
            result,
            {
                "member": "bob",
                "permission": PERMISSION_READ,
                "roles": [],
                "allowed": False,
                "reason": "成员未配置",
            },
            f"未配置成员的查询结果与预期不符，输入为 bob/{PERMISSION_READ}，"
            f"实际为 {result!r}",
        )

    def test_check_is_read_only(self):
        self.assert_success_json(
            self.grant("reader", PERMISSION_READ), "授予 reader/documents:read"
        )
        rules_before = self.stored_rules()

        for member, permission in (
            ("alice", PERMISSION_READ),
            ("alice", PERMISSION_WRITE),
            ("bob", PERMISSION_READ),
        ):
            proc = self.check(member, permission)
            self.assert_success_json(
                proc, f"只读性核对，查询 {member}/{permission}"
            )

        rules_after = self.stored_rules()
        self.assertEqual(
            rules_before,
            rules_after,
            f"查询前后授权记录应一致，查询前 {rules_before!r}，查询后 {rules_after!r}",
        )

    # ---- 撤销授权 -------------------------------------------------------

    def test_revoke_existing_grant_denies_and_persists(self):
        self.assert_success_json(
            self.grant("reader", PERMISSION_READ), "预置授权 reader/documents:read"
        )

        revoke_result = self.assert_success_json(
            self.revoke("reader", PERMISSION_READ), "撤销 reader/documents:read"
        )
        self.assertEqual(
            revoke_result,
            {"role": "reader", "permission": PERMISSION_READ, "revoked": True},
            f"撤销已有规则应返回 revoked=true，实际为 {revoke_result!r}",
        )
        self.assertEqual(
            self.stored_rules(),
            [],
            f"撤销后授权记录应为空，实际为 {self.stored_rules()!r}",
        )

        # 撤销后 alice 仍固定拥有 reader 角色，但该权限不再授予。
        check_result = self.assert_success_json(
            self.check("alice", PERMISSION_READ), "撤销后查询 alice/documents:read"
        )
        self.assertEqual(
            check_result,
            {
                "member": "alice",
                "permission": PERMISSION_READ,
                "roles": ["reader"],
                "allowed": False,
                "reason": "权限未授予",
            },
            f"撤销后查询结果与预期不符，实际为 {check_result!r}",
        )

        # 重新打开同一数据库文件：撤销结果必须持久化。
        reopened_result = self.assert_success_json(
            self.check("alice", PERMISSION_READ), "重新打开数据库后再次查询"
        )
        self.assertEqual(
            reopened_result,
            check_result,
            f"重新打开数据库后结果发生变化，实际为 {reopened_result!r}",
        )

        # 再次授予同一规则后恢复允许。
        self.assert_success_json(
            self.grant("reader", PERMISSION_READ), "撤销后重新授予"
        )
        regranted_result = self.assert_success_json(
            self.check("alice", PERMISSION_READ), "重新授予后查询"
        )
        self.assertEqual(
            regranted_result["allowed"],
            True,
            f"重新授予后应恢复允许，实际为 {regranted_result!r}",
        )

    def test_revoke_missing_rule_returns_false(self):
        # 数据库文件尚不存在：沿用建库行为，按未删除处理。
        revoke_result = self.assert_success_json(
            self.revoke("reader", PERMISSION_READ), "撤销不存在的规则（新建库）"
        )
        self.assertEqual(
            revoke_result,
            {"role": "reader", "permission": PERMISSION_READ, "revoked": False},
            f"规则不存在时应返回 revoked=false，实际为 {revoke_result!r}",
        )
        self.assertTrue(
            os.path.exists(self.db_path),
            "父目录存在时撤销应沿用建库行为创建数据库文件",
        )

        # 没有对应授权的非空角色名称同样按未删除处理，不另报角色不存在。
        unknown_role_result = self.assert_success_json(
            self.revoke("nobody", PERMISSION_READ), "撤销从未授权的角色"
        )
        self.assertEqual(
            unknown_role_result,
            {"role": "nobody", "permission": PERMISSION_READ, "revoked": False},
            f"未知角色应返回 revoked=false，实际为 {unknown_role_result!r}",
        )

        # 重复撤销同一规则：第一次 true，第二次 false，均成功。
        self.assert_success_json(
            self.grant("reader", PERMISSION_READ), "授予 reader/documents:read"
        )
        first = self.assert_success_json(
            self.revoke("reader", PERMISSION_READ), "第一次撤销"
        )
        second = self.assert_success_json(
            self.revoke("reader", PERMISSION_READ), "重复撤销"
        )
        self.assertTrue(first["revoked"], f"第一次撤销应为 true，实际为 {first!r}")
        self.assertFalse(
            second["revoked"], f"重复撤销应为 false，实际为 {second!r}"
        )

    def test_revoke_does_not_touch_other_grants(self):
        self.assert_success_json(
            self.grant("reader", PERMISSION_READ), "授予 reader/documents:read"
        )
        self.assert_success_json(
            self.grant("reader", PERMISSION_WRITE), "授予 reader/documents:write"
        )
        self.assert_success_json(
            self.grant("editor", PERMISSION_READ), "授予 editor/documents:read"
        )

        self.assert_success_json(
            self.revoke("reader", PERMISSION_READ), "撤销 reader/documents:read"
        )

        rules = self.stored_rules()
        self.assertEqual(
            rules,
            [("editor", PERMISSION_READ), ("reader", PERMISSION_WRITE)],
            f"撤销不应影响其他角色或权限的授权，实际记录为 {rules!r}",
        )

        # alice 与 reader 的固定关系不变：其他权限仍允许。
        write_result = self.assert_success_json(
            self.check("alice", PERMISSION_WRITE), "撤销后查询 documents:write"
        )
        self.assertEqual(
            write_result,
            {
                "member": "alice",
                "permission": PERMISSION_WRITE,
                "roles": ["reader"],
                "allowed": True,
                "reason": "直接角色授权",
            },
            f"未被撤销的权限应继续允许，实际为 {write_result!r}",
        )

    def test_revoke_trims_whitespace_and_matches_exactly(self):
        self.assert_success_json(
            self.grant("reader", PERMISSION_READ), "授予 reader/documents:read"
        )

        # 带首尾空白的名称规整后命中同一规则。
        revoke_result = self.assert_success_json(
            self.revoke("  reader\t", f"\n{PERMISSION_READ} "), "带首尾空白的 revoke"
        )
        self.assertEqual(
            revoke_result,
            {"role": "reader", "permission": PERMISSION_READ, "revoked": True},
            f"revoke 应返回规整后的名称，实际为 {revoke_result!r}",
        )

        # 大小写不同或通配符形态的名称不命中已有规则。
        self.assert_success_json(
            self.grant("reader", PERMISSION_READ), "重新授予 reader/documents:read"
        )
        for role, permission in (
            ("Reader", PERMISSION_READ),
            ("reader", "documents:Read"),
            ("reader", "documents:*"),
            ("reader", "documents:%"),
        ):
            with self.subTest(role=role, permission=permission):
                result = self.assert_success_json(
                    self.revoke(role, permission), f"撤销 {role}/{permission}"
                )
                self.assertFalse(
                    result["revoked"],
                    f"{role}/{permission} 不应命中 documents:read，实际为 {result!r}",
                )
        self.assertEqual(
            self.stored_rules(),
            [("reader", PERMISSION_READ)],
            f"精确匹配之外的撤销不应删除已有规则，实际为 {self.stored_rules()!r}",
        )

    def test_revoke_empty_or_blank_names_are_invalid(self):
        cases = [
            ("", PERMISSION_READ),
            ("reader", ""),
            ("   ", PERMISSION_READ),
            ("reader", "\t \n"),
            ("", ""),
        ]
        for index, (role, permission) in enumerate(cases):
            with self.subTest(role=role, permission=permission):
                fresh_db = os.path.join(self.tmpdir, f"revoke_invalid_{index}.db")
                argv = ("revoke", role, permission)
                proc = self.run_rbac(*argv, db=fresh_db)
                self.assert_invalid_name(proc, argv, fresh_db_path=fresh_db)

    def test_revoke_invalid_name_does_not_change_existing_grants(self):
        self.assert_success_json(
            self.grant("reader", PERMISSION_READ), "预置一条授权"
        )
        rules_before = self.stored_rules()

        for argv in (
            ("revoke", "", PERMISSION_READ),
            ("revoke", "reader", "   "),
        ):
            with self.subTest(argv=argv):
                self.assert_invalid_name(self.run_rbac(*argv), argv)

        self.assertEqual(
            rules_before,
            self.stored_rules(),
            f"非法名称的撤销不应改变已有授权，之前 {rules_before!r}，"
            f"之后 {self.stored_rules()!r}",
        )

    def test_revoke_missing_parent_directory_is_storage_error(self):
        missing_parent_db = os.path.join(self.tmpdir, "missing_dir", "rules.db")
        argv = ("revoke", "reader", PERMISSION_READ)
        proc = self.run_rbac(*argv, db=missing_parent_db)
        self.assert_storage_error(proc, argv)

    def test_revoke_invalid_name_takes_precedence_over_storage_error(self):
        missing_parent_db = os.path.join(self.tmpdir, "missing_dir", "rules.db")
        argv = ("revoke", " ", "")
        proc = self.run_rbac(*argv, db=missing_parent_db)
        self.assert_invalid_name(proc, argv, fresh_db_path=missing_parent_db)

    # ---- 名称边界 -------------------------------------------------------

    def test_surrounding_whitespace_is_trimmed(self):
        grant_result = self.assert_success_json(
            self.grant("  reader\t", "\ndocuments:read "), "带首尾空白的 grant"
        )
        # 返回结果使用规整后的名称。
        self.assertEqual(
            grant_result,
            {"role": "reader", "permission": PERMISSION_READ},
            f"grant 应返回规整后的名称，实际为 {grant_result!r}",
        )

        check_result = self.assert_success_json(
            self.check("\talice\n", f"  {PERMISSION_READ}  "), "带首尾空白的 check"
        )
        self.assertEqual(
            check_result,
            {
                "member": "alice",
                "permission": PERMISSION_READ,
                "roles": ["reader"],
                "allowed": True,
                "reason": "直接角色授权",
            },
            f"check 应返回规整后的名称并允许，实际为 {check_result!r}",
        )

        rules = self.stored_rules()
        self.assertEqual(
            rules,
            [("reader", PERMISSION_READ)],
            f"空白规整后应只入库规整名称，实际记录为 {rules!r}",
        )

    def test_name_matching_is_case_sensitive(self):
        self.assert_success_json(
            self.grant("reader", PERMISSION_READ), "授予 reader/documents:read"
        )

        # Alice 不应被当作 alice：按未配置成员处理。
        member_result = self.assert_success_json(
            self.check("Alice", PERMISSION_READ), "大小写不同的成员 Alice"
        )
        self.assertEqual(
            member_result,
            {
                "member": "Alice",
                "permission": PERMISSION_READ,
                "roles": [],
                "allowed": False,
                "reason": "成员未配置",
            },
            f"Alice 不应命中 alice，实际为 {member_result!r}",
        )

        # documents:Read 不应命中 documents:read：角色存在但权限未授予。
        permission_result = self.assert_success_json(
            self.check("alice", "documents:Read"), "大小写不同的权限 documents:Read"
        )
        self.assertEqual(
            permission_result,
            {
                "member": "alice",
                "permission": "documents:Read",
                "roles": ["reader"],
                "allowed": False,
                "reason": "权限未授予",
            },
            f"documents:Read 不应命中 documents:read，实际为 {permission_result!r}",
        )

    def test_empty_or_blank_names_are_invalid_and_create_no_database(self):
        cases = [
            ("grant", "", PERMISSION_READ),
            ("grant", "reader", ""),
            ("grant", "   ", PERMISSION_READ),
            ("grant", "reader", "\t \n"),
            ("grant", "", ""),
            ("check", "", PERMISSION_READ),
            ("check", "alice", ""),
            ("check", "   ", PERMISSION_READ),
            ("check", "alice", "  "),
            ("check", "\t", "\n"),
        ]
        for index, (command, first, second) in enumerate(cases):
            with self.subTest(command=command, first=first, second=second):
                fresh_db = os.path.join(self.tmpdir, f"invalid_{index}.db")
                argv = (command, first, second)
                proc = self.run_rbac(*argv, db=fresh_db)
                self.assert_invalid_name(proc, argv, fresh_db_path=fresh_db)

    def test_invalid_name_does_not_change_existing_grants(self):
        self.assert_success_json(
            self.grant("reader", PERMISSION_READ), "预置一条授权"
        )
        rules_before = self.stored_rules()

        for argv in (
            ("grant", "", PERMISSION_WRITE),
            ("grant", "reader", "   "),
            ("check", " ", PERMISSION_READ),
            ("check", "alice", ""),
        ):
            with self.subTest(argv=argv):
                self.assert_invalid_name(self.run_rbac(*argv), argv)

        rules_after = self.stored_rules()
        self.assertEqual(
            rules_before,
            rules_after,
            f"非法名称调用不应改变已有授权，之前 {rules_before!r}，之后 {rules_after!r}",
        )

    # ---- 存储失败 -------------------------------------------------------

    def test_missing_parent_directory_is_storage_error(self):
        missing_parent_db = os.path.join(self.tmpdir, "missing_dir", "rules.db")
        self.assertFalse(
            os.path.exists(os.path.dirname(missing_parent_db)),
            "测试前置：父目录应不存在",
        )

        for argv in (
            ("grant", "reader", PERMISSION_READ),
            ("check", "alice", PERMISSION_READ),
        ):
            with self.subTest(argv=argv):
                proc = self.run_rbac(*argv, db=missing_parent_db)
                self.assert_storage_error(proc, argv)

    def test_invalid_name_takes_precedence_over_storage_error(self):
        # 同一条父目录不存在的路径，配合空名称时应优先判定 invalid_name。
        missing_parent_db = os.path.join(self.tmpdir, "missing_dir", "rules.db")
        argv = ("grant", " ", "")
        proc = self.run_rbac(*argv, db=missing_parent_db)
        self.assert_invalid_name(proc, argv, fresh_db_path=missing_parent_db)


if __name__ == "__main__":
    unittest.main()
