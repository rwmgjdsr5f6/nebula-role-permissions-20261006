"""list-permission-members 按权限反获准成员入口的回归测试。

只依赖 Python 3 标准库；每个用例使用独立临时数据库目录，结束后自动清理。
从项目根目录执行：

    python -m unittest discover -s tests

通过 `python -m rbac` 子进程走完整公开命令行入口，覆盖范围：
- reader 获授 documents:read 与 documents:write、editor 获授 documents:read
  时，反查 documents:read 只得 alice（其直接角色 reader 获授该权限），
  editor 未绑定任何固定成员，不进入结果；documents:write 无获准成员；
- 其他权限的授权不混入；固定成员未配置的角色即使直接获授也被忽略；
  输出仅含 permission、members 两个字段，成员项仅含 member、roles；
- 撤销 reader 的读取授权后反查即时收窄为空成员数组，重新打开同一规则库
  结果一致；权限从未授予或授权全部撤销时返回空成员数组；
- 星号、百分号、下划线按普通字符做大小写敏感的完整名称匹配，首尾空白被
  去除且输出使用规整后的权限名；查询只读，调用前后全部授权记录一致；
- 父目录存在而规则库文件尚不存在时查询会创建可用空库并返回空成员数组；
- 权限名为空或纯空白：退出码 2，stdout 为空，stderr 恰为
  {"error":"invalid_name"} 加换行，不建库、不改已有授权，且即使父目录
  不存在也优先得到此结果；
- 名称有效但数据库打不开或规则表缺列：退出码 1，stdout 为空，stderr 恰为
  {"error":"storage_error"} 加换行，不输出空成员结果或异常堆栈。
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


class ListPermissionMembersTests(unittest.TestCase):
    """通过 `python -m rbac` 子进程核对按权限反查获准成员入口的对外行为。"""

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

    def list_permission_members(self, permission, **kwargs):
        return self.run_rbac("list-permission-members", permission, **kwargs)

    def assert_success_member_lookup(self, proc, permission):
        """成功查询：退出码 0、stderr 为空，stdout 恰为反查 JSON 加换行。

        返回解析后的对象，并核对输出只含 permission、members 两个字段，
        成员项只含 member、roles 两个字段。
        """
        argv = ("list-permission-members", permission)
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
            {"permission", "members"},
            f"输入 {argv!r}：输出应只含 permission、members 两个字段，"
            f"实际键为 {set(result.keys())}",
        )
        for item in result["members"]:
            self.assertEqual(
                set(item.keys()),
                {"member", "roles"},
                f"输入 {argv!r}：成员项应只含 member、roles 两个字段，"
                f"实际键为 {set(item.keys())}",
            )
        return result

    def assert_lookup_equals(self, proc, permission, expected_members):
        """核对一次成功反查的完整结果（含标准输出字节形态）。"""
        result = self.assert_success_member_lookup(proc, permission)
        expected = {"permission": permission.strip(), "members": expected_members}
        self.assertEqual(
            result,
            expected,
            f"输入 list-permission-members {permission!r}：期望 {expected!r}，"
            f"实际为 {result!r}",
        )
        # 紧凑 UTF-8 JSON：确保对外字节形态恰为一个对象加换行。
        expected_stdout = (
            json.dumps(expected, ensure_ascii=False, separators=(",", ":")) + "\n"
        )
        self.assertEqual(
            proc.stdout,
            expected_stdout,
            f"输入 list-permission-members {permission!r}："
            f"标准输出字节形态与预期不符，期望 {expected_stdout!r}，"
            f"实际为 {proc.stdout!r}",
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
        self.assertNotIn(
            "Traceback",
            proc.stderr,
            f"输入 {argv!r}：标准错误不得包含异常堆栈，实际为 {proc.stderr!r}",
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

    # ---- 反查主流程 -----------------------------------------------------

    def test_acceptance_read_returns_alice_with_reader_write_empty(self):
        # 验收规则库：reader 获授读、写；editor 获授读。
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("reader", PERMISSION_WRITE).check_returncode()
        self.grant("editor", PERMISSION_READ).check_returncode()

        # editor 未绑定任何固定成员，不进入结果；alice 经 reader 获准读取。
        proc = self.list_permission_members(PERMISSION_READ)
        result = self.assert_lookup_equals(
            proc,
            PERMISSION_READ,
            [{"member": "alice", "roles": ["reader"]}],
        )

        # 成员不重复、成员内角色去重。
        members = [item["member"] for item in result["members"]]
        self.assertEqual(
            len(members),
            len(set(members)),
            f"成员不应重复，实际为 {members!r}",
        )
        for item in result["members"]:
            self.assertEqual(
                item["roles"],
                sorted(set(item["roles"])),
                f"成员 {item['member']!r} 的角色应去重并按码点升序，"
                f"实际为 {item['roles']!r}",
            )

        # documents:write 只授给了 reader，但反查成员同样应得到 alice。
        # （写权限同样绑定 reader；此处另核对题述未授予场景用独立用例。）
        self.assert_lookup_equals(
            self.list_permission_members(PERMISSION_WRITE),
            PERMISSION_WRITE,
            [{"member": "alice", "roles": ["reader"]}],
        )

    def test_permission_granted_only_to_unbound_role_returns_empty_members(self):
        # editor 没有任何固定成员：即使直接获授 documents:read，
        # 反查获准成员仍为空。
        self.grant("editor", PERMISSION_READ).check_returncode()
        self.assert_lookup_equals(
            self.list_permission_members(PERMISSION_READ), PERMISSION_READ, []
        )

    def test_other_permissions_grants_are_not_mixed_in(self):
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("editor", PERMISSION_EXPORT).check_returncode()

        # editor 的 documents:export 与 documents:read 无关，不得混入；
        # 反查 documents:export 时 editor 无成员，结果为空。
        self.assert_lookup_equals(
            self.list_permission_members(PERMISSION_READ),
            PERMISSION_READ,
            [{"member": "alice", "roles": ["reader"]}],
        )
        self.assert_lookup_equals(
            self.list_permission_members(PERMISSION_EXPORT), PERMISSION_EXPORT, []
        )

    def test_revoke_reader_read_narrows_lookup_and_persists_on_reopen(self):
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("editor", PERMISSION_READ).check_returncode()

        revoke_proc = self.revoke("reader", PERMISSION_READ)
        self.assertEqual(
            revoke_proc.returncode,
            0,
            f"撤销准备失败：stdout={revoke_proc.stdout!r}，"
            f"stderr={revoke_proc.stderr!r}",
        )

        # reader 被撤销后只剩未绑定成员的 editor，获准成员为空。
        proc = self.list_permission_members(PERMISSION_READ)
        self.assert_lookup_equals(proc, PERMISSION_READ, [])

        # 每次调用都重新打开同一规则库：撤销后的收窄结果必须持久化。
        reopened_proc = self.list_permission_members(PERMISSION_READ)
        self.assert_lookup_equals(reopened_proc, PERMISSION_READ, [])
        self.assertEqual(
            reopened_proc.stdout,
            proc.stdout,
            f"重新打开同一规则库后结果应一致，首次 {proc.stdout!r}，"
            f"重开后 {reopened_proc.stdout!r}",
        )

    def test_never_granted_or_fully_revoked_returns_empty_members(self):
        # 空库上反查从未授予的权限：空成员数组。
        self.assert_lookup_equals(
            self.list_permission_members(PERMISSION_READ), PERMISSION_READ, []
        )

        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("editor", PERMISSION_READ).check_returncode()
        # 全部撤销后再次反查：同样为空成员数组。
        self.revoke("reader", PERMISSION_READ).check_returncode()
        self.revoke("editor", PERMISSION_READ).check_returncode()
        self.assert_lookup_equals(
            self.list_permission_members(PERMISSION_READ), PERMISSION_READ, []
        )

    def test_wildcard_chars_are_literal_and_match_is_case_sensitive(self):
        # "*"、"%"、"_" 都是权限名的普通字符，不做通配匹配。
        wildcard_permission = "docs:*_%read"
        self.grant("reader", wildcard_permission).check_returncode()

        self.assert_lookup_equals(
            self.list_permission_members(wildcard_permission),
            wildcard_permission,
            [{"member": "alice", "roles": ["reader"]}],
        )
        for other in ("docs:%read", "docs:*_read", "docs:X_%read", "docs:*_%READ"):
            with self.subTest(other=other):
                self.assert_lookup_equals(
                    self.list_permission_members(other), other, []
                )

        # 普通大小写差异同样不匹配。
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.assert_lookup_equals(
            self.list_permission_members("DOCUMENTS:READ"), "DOCUMENTS:READ", []
        )

    def test_permission_name_surrounding_whitespace_is_trimmed(self):
        self.grant("reader", PERMISSION_READ).check_returncode()

        # 带首尾空白的权限名规整后匹配；输出使用规整后的名称。
        proc = self.list_permission_members("\t documents:read \n")
        result = self.assert_success_member_lookup(proc, "\t documents:read \n")
        self.assertEqual(
            result,
            {
                "permission": PERMISSION_READ,
                "members": [{"member": "alice", "roles": ["reader"]}],
            },
            f"带空白名称的反查结果与预期不符，实际为 {result!r}",
        )

    def test_permission_query_is_read_only(self):
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("reader", PERMISSION_WRITE).check_returncode()
        self.grant("editor", PERMISSION_READ).check_returncode()
        rules_before = self.stored_rules()

        # 正常查询前后（含已授予、未授予、带空白权限名）全部授权记录一致。
        for permission in (
            PERMISSION_READ,
            PERMISSION_WRITE,
            PERMISSION_EXPORT,
            "  documents:read\t",
        ):
            with self.subTest(permission=permission):
                proc = self.list_permission_members(permission)
                self.assert_success_member_lookup(proc, permission)

        self.assertEqual(
            self.stored_rules(),
            rules_before,
            f"按权限反查成员应为只读：查询前 {rules_before!r}，"
            f"查询后 {self.stored_rules()!r}",
        )

    def test_missing_db_with_existing_parent_is_created_and_returns_empty(self):
        self.assertFalse(
            os.path.exists(self.db_path), "测试前置：规则库文件应尚未创建"
        )

        # 父目录已存在而文件不存在：反查应创建可用空库并返回空成员数组。
        proc = self.list_permission_members(PERMISSION_READ)
        self.assert_lookup_equals(proc, PERMISSION_READ, [])
        self.assertTrue(
            os.path.exists(self.db_path),
            "父目录存在时查询应创建规则库文件",
        )

        # 创建出的库必须可用：授权后再次查询即可看到 alice。
        self.grant("reader", PERMISSION_READ).check_returncode()
        followup = self.list_permission_members(PERMISSION_READ)
        self.assert_lookup_equals(
            followup,
            PERMISSION_READ,
            [{"member": "alice", "roles": ["reader"]}],
        )

    # ---- 错误边界 -------------------------------------------------------

    def test_empty_or_blank_permission_is_invalid_and_creates_no_database(self):
        for index, permission in enumerate(("", "   ", "\t \n")):
            with self.subTest(permission=permission):
                fresh_db = os.path.join(self.tmpdir, f"permission_invalid_{index}.db")
                argv = ("list-permission-members", permission)
                proc = self.run_rbac(*argv, db=fresh_db)
                self.assert_invalid_name(proc, argv, fresh_db_path=fresh_db)

    def test_invalid_permission_does_not_change_existing_grants(self):
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("editor", PERMISSION_EXPORT).check_returncode()
        rules_before = self.stored_rules()

        for permission in ("", "   ", "\t\n "):
            with self.subTest(permission=permission):
                argv = ("list-permission-members", permission)
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
        argv = ("list-permission-members", " ")
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

        argv = ("list-permission-members", PERMISSION_READ)
        proc = self.run_rbac(*argv, db=missing_parent_db)
        self.assert_storage_error(proc, argv)

        # 不得夹带任何成功结果或异常堆栈。
        self.assertNotIn(
            "members",
            proc.stdout,
            f"输入 {argv!r}：存储失败不得输出成功结果，实际为 {proc.stdout!r}",
        )

    def test_non_sqlite_file_is_storage_error(self):
        # 文件存在但内容不是 SQLite：初始化建表失败，必须报存储错误，
        # 不能退化为空成员结果，文件字节保持不变。
        with open(self.db_path, "wb") as handle:
            handle.write(b"x" * 128)

        argv = ("list-permission-members", PERMISSION_READ)
        proc = self.run_rbac(*argv)
        self.assert_storage_error(proc, argv)
        with open(self.db_path, "rb") as handle:
            self.assertEqual(handle.read(), b"x" * 128)

    def test_incompatible_schema_missing_column_is_storage_error(self):
        # 预置同名但缺少 role/permission 列的表：查询缺列必须报存储错误。
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("CREATE TABLE role_permissions (a TEXT, b TEXT)")
            conn.commit()

        argv = ("list-permission-members", PERMISSION_READ)
        proc = self.run_rbac(*argv)
        self.assert_storage_error(proc, argv)


if __name__ == "__main__":
    unittest.main()
