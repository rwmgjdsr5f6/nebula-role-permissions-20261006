"""list-role-members 按角色查询固定关联成员入口的回归测试。

只依赖 Python 3 标准库；每个用例使用独立临时数据库目录，结束后自动清理。
从项目根目录执行：

    python -m unittest discover -s tests

通过 `python -m rbac` 子进程走完整公开命令行入口，覆盖范围：
- 空规则库查询 reader 返回 {"role":"reader","members":["alice"]}，
  查询 editor 返回 {"role":"editor","members":[]}（正常空结果）；
- 结果只取决于固定成员关系，与当前授权无关：角色获授或撤销权限后
  成员结果不变；未关联成员的角色即使获授权限仍返回空数组；
- 角色名大小写敏感（Reader 不匹配 reader），"*"、"%"、"_" 为普通字符，
  首尾空白被去除且输出使用规整后的角色名，内部空白保留；
- 输出仅含 role、members 两个字段，members 为成员名字符串数组；
- 查询只读，调用前后全部授权记录一致；
- 父目录存在而规则库文件尚不存在时查询会创建可用空库并返回成员结果；
- 角色名为空或纯空白：退出码 2，stdout 为空，stderr 恰为
  {"error":"invalid_name"} 加换行，不建库、不改已有授权，且即使父目录
  不存在也优先得到此结果；
- 名称有效但数据库打不开或规则文件不是 SQLite：退出码 1，stdout 为空，
  stderr 恰为 {"error":"storage_error"} 加换行，不输出成员结果或异常堆栈。
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


class ListRoleMembersTests(unittest.TestCase):
    """通过 `python -m rbac` 子进程核对按角色查询固定成员入口的对外行为。"""

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

    def list_role_members(self, role, **kwargs):
        return self.run_rbac("list-role-members", role, **kwargs)

    def assert_success_member_lookup(self, proc, role):
        """成功查询：退出码 0、stderr 为空，stdout 恰为成员 JSON 加换行。

        返回解析后的对象，并核对输出只含 role、members 两个字段，
        members 为字符串数组。
        """
        argv = ("list-role-members", role)
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
            {"role", "members"},
            f"输入 {argv!r}：输出应只含 role、members 两个字段，"
            f"实际键为 {set(result.keys())}",
        )
        self.assertIsInstance(
            result["members"],
            list,
            f"输入 {argv!r}：members 应为数组，实际为 {result['members']!r}",
        )
        for member in result["members"]:
            self.assertIsInstance(
                member,
                str,
                f"输入 {argv!r}：成员项应为字符串，实际为 {member!r}",
            )
        return result

    def assert_lookup_equals(self, proc, role, expected_members):
        """核对一次成功查询的完整结果（含标准输出字节形态）。"""
        result = self.assert_success_member_lookup(proc, role)
        expected = {"role": role.strip(), "members": expected_members}
        self.assertEqual(
            result,
            expected,
            f"输入 list-role-members {role!r}：期望 {expected!r}，"
            f"实际为 {result!r}",
        )
        # 紧凑 UTF-8 JSON：确保对外字节形态恰为一个对象加换行。
        expected_stdout = (
            json.dumps(expected, ensure_ascii=False, separators=(",", ":")) + "\n"
        )
        self.assertEqual(
            proc.stdout,
            expected_stdout,
            f"输入 list-role-members {role!r}："
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

    # ---- 验收样例 -------------------------------------------------------

    def test_acceptance_empty_db_reader_returns_alice(self):
        # 验收样例：空规则库查询 reader 仍返回 alice（固定成员关系）。
        self.assert_lookup_equals(
            self.list_role_members("reader"), "reader", ["alice"]
        )

    def test_acceptance_empty_db_editor_returns_empty_members(self):
        # 验收样例：空规则库查询 editor 返回空成员数组（正常空结果）。
        self.assert_lookup_equals(self.list_role_members("editor"), "editor", [])

    def test_result_independent_of_current_grants(self):
        # reader 未获授任何权限时已有 alice；授予、撤销权限后结果不变。
        self.assert_lookup_equals(
            self.list_role_members("reader"), "reader", ["alice"]
        )
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("reader", PERMISSION_WRITE).check_returncode()
        self.assert_lookup_equals(
            self.list_role_members("reader"), "reader", ["alice"]
        )
        self.revoke("reader", PERMISSION_READ).check_returncode()
        self.revoke("reader", PERMISSION_WRITE).check_returncode()
        self.assert_lookup_equals(
            self.list_role_members("reader"), "reader", ["alice"]
        )

    def test_unbound_role_with_grants_still_returns_empty_members(self):
        # editor 未关联任何固定成员：即使获授权限，查询仍返回空数组。
        self.grant("editor", PERMISSION_READ).check_returncode()
        self.assert_lookup_equals(self.list_role_members("editor"), "editor", [])

    def test_never_seen_role_returns_empty_members(self):
        self.assert_lookup_equals(
            self.list_role_members("auditor"), "auditor", []
        )

    # ---- 名称匹配规则 ---------------------------------------------------

    def test_role_name_match_is_case_sensitive(self):
        # Reader 不匹配 reader：大小写不同的完整名称视为不同角色。
        for other in ("Reader", "READER", "readeR"):
            with self.subTest(role=other):
                self.assert_lookup_equals(self.list_role_members(other), other, [])

    def test_wildcard_chars_are_literal(self):
        # "*"、"%"、"_" 都是角色名的普通字符，不做通配匹配。
        for other in ("read%", "rea_er", "read*", "*"):
            with self.subTest(role=other):
                self.assert_lookup_equals(self.list_role_members(other), other, [])

    def test_role_name_surrounding_whitespace_is_trimmed(self):
        # 带首尾空白的角色名规整后匹配；输出使用规整后的名称。
        proc = self.list_role_members("\t reader \n")
        result = self.assert_success_member_lookup(proc, "\t reader \n")
        self.assertEqual(
            result,
            {"role": "reader", "members": ["alice"]},
            f"带空白名称的查询结果与预期不符，实际为 {result!r}",
        )

    def test_role_name_inner_whitespace_is_preserved(self):
        # 内部空白保留："read er" 是不同于 reader 的完整名称。
        self.assert_lookup_equals(
            self.list_role_members("read er"), "read er", []
        )

    # ---- 只读与初始化行为 -----------------------------------------------

    def test_query_is_read_only(self):
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("editor", PERMISSION_READ).check_returncode()
        rules_before = self.stored_rules()

        for role in ("reader", "editor", "auditor", "  reader\t"):
            with self.subTest(role=role):
                proc = self.list_role_members(role)
                self.assert_success_member_lookup(proc, role)

        self.assertEqual(
            self.stored_rules(),
            rules_before,
            f"按角色查询成员应为只读：查询前 {rules_before!r}，"
            f"查询后 {self.stored_rules()!r}",
        )

    def test_missing_db_with_existing_parent_is_created_and_returns_members(self):
        self.assertFalse(
            os.path.exists(self.db_path), "测试前置：规则库文件应尚未创建"
        )

        # 父目录已存在而文件不存在：查询应创建可用空库并返回成员结果。
        proc = self.list_role_members("reader")
        self.assert_lookup_equals(proc, "reader", ["alice"])
        self.assertTrue(
            os.path.exists(self.db_path),
            "父目录存在时查询应创建规则库文件",
        )

        # 创建出的库必须可用：授权后其他命令可正常读写。
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.assertEqual(
            self.stored_rules(), [("reader", PERMISSION_READ)]
        )

    # ---- 错误边界 -------------------------------------------------------

    def test_empty_or_blank_role_is_invalid_and_creates_no_database(self):
        for index, role in enumerate(("", "   ", "\t \n")):
            with self.subTest(role=role):
                fresh_db = os.path.join(self.tmpdir, f"role_invalid_{index}.db")
                argv = ("list-role-members", role)
                proc = self.run_rbac(*argv, db=fresh_db)
                self.assert_invalid_name(proc, argv, fresh_db_path=fresh_db)

    def test_invalid_role_does_not_change_existing_grants(self):
        self.grant("reader", PERMISSION_READ).check_returncode()
        rules_before = self.stored_rules()

        for role in ("", "   ", "\t\n "):
            with self.subTest(role=role):
                argv = ("list-role-members", role)
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
        argv = ("list-role-members", " ")
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

        argv = ("list-role-members", "reader")
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
        # 不能退化为成员结果，文件字节保持不变。
        with open(self.db_path, "wb") as handle:
            handle.write(b"x" * 128)

        argv = ("list-role-members", "reader")
        proc = self.run_rbac(*argv)
        self.assert_storage_error(proc, argv)
        with open(self.db_path, "rb") as handle:
            self.assertEqual(handle.read(), b"x" * 128)

    def test_incompatible_schema_missing_column_is_storage_error(self):
        # 预置同名但缺少 role/permission 列的表：即便本查询不读规则表，
        # 其他命令仍需可用结构；此处核对缺列时既有命令报存储错误，
        # 且本命令结果仍只取决于固定成员关系。
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("CREATE TABLE role_permissions (a TEXT, b TEXT)")
            conn.commit()

        argv = ("list-permissions", "reader")
        proc = self.run_rbac(*argv)
        self.assert_storage_error(proc, argv)


if __name__ == "__main__":
    unittest.main()
