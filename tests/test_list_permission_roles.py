"""list-permission-roles 按权限反查直接角色入口的回归测试。

只依赖 Python 3 标准库；每个用例使用独立临时数据库目录，结束后自动清理。
从项目根目录执行：

    python -m unittest discover -s tests

通过 `python -m rbac` 子进程走完整公开命令行入口，覆盖范围：
- 反查只含直接获授该权限的角色：其他权限的角色不混入，未配置成员的
  角色（editor）照常计入，角色去重后按 Unicode 码点升序排列，输出仅含
  permission、roles 两个字段；
- 撤销某角色的授权后反查即时收窄，重新打开同一规则库结果一致；
- 权限从未授予或授权已全部撤销时返回空角色数组；
- 权限名首尾空白被去除，输出使用规整后的权限；星号、百分号、下划线
  按普通字符精确匹配；查询只读，调用前后全部授权记录一致；
- 父目录存在而规则库文件尚不存在时查询会创建可用空库并返回空角色数组；
- 权限为空或纯空白：退出码 2，stdout 为空，stderr 恰为
  {"error":"invalid_name"} 加换行，不建库、不改已有授权，且即使父目录
  不存在也优先得到此结果；
- 权限有效但父目录不存在：退出码 1，stdout 为空，stderr 恰为
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


class ListPermissionRolesTests(unittest.TestCase):
    """通过 `python -m rbac` 子进程核对按权限反查角色入口的对外行为。"""

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

    def list_permission_roles(self, permission, **kwargs):
        return self.run_rbac("list-permission-roles", permission, **kwargs)

    def assert_success_role_listing(self, proc, permission):
        """成功查询：退出码 0、stderr 为空，stdout 恰为反查 JSON 加换行。

        返回解析后的对象，并核对输出只含 permission、roles 两个字段。
        """
        argv = ("list-permission-roles", permission)
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
            {"permission", "roles"},
            f"输入 {argv!r}：输出应只含 permission、roles 两个字段，"
            f"实际键为 {set(result.keys())}",
        )
        return result

    def assert_listing_equals(self, proc, permission, expected_roles):
        """核对一次成功反查的完整结果（含标准输出字节形态）。"""
        result = self.assert_success_role_listing(proc, permission)
        expected = {
            "permission": permission.strip(),
            "roles": expected_roles,
        }
        self.assertEqual(
            result,
            expected,
            f"输入 list-permission-roles {permission!r}：期望 {expected!r}，"
            f"实际为 {result!r}",
        )
        # 紧凑 UTF-8 JSON：确保对外字节形态恰为一个对象加换行。
        expected_stdout = (
            json.dumps(expected, ensure_ascii=False, separators=(",", ":")) + "\n"
        )
        self.assertEqual(
            proc.stdout,
            expected_stdout,
            f"输入 list-permission-roles {permission!r}：标准输出字节形态与预期不符，"
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

    # ---- 反查主流程 -----------------------------------------------------

    def test_read_permission_returns_editor_and_reader_sorted(self):
        # 验收主场景：reader 获授读、写，editor 仅获授读。
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("reader", PERMISSION_WRITE).check_returncode()
        self.grant("editor", PERMISSION_READ).check_returncode()

        # 码点升序：editor < reader；写权限只属于 reader。
        self.assert_listing_equals(
            self.list_permission_roles(PERMISSION_READ),
            PERMISSION_READ,
            ["editor", "reader"],
        )
        self.assert_listing_equals(
            self.list_permission_roles(PERMISSION_WRITE),
            PERMISSION_WRITE,
            ["reader"],
        )

    def test_other_permissions_roles_are_not_mixed_in(self):
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("editor", PERMISSION_EXPORT).check_returncode()

        # editor 只有 export 授权，不得混入 read 的反查结果。
        self.assert_listing_equals(
            self.list_permission_roles(PERMISSION_READ), PERMISSION_READ, ["reader"]
        )
        self.assertEqual(
            self.stored_rules(),
            [("editor", PERMISSION_EXPORT), ("reader", PERMISSION_READ)],
            f"授权记录与预置不符，实际为 {self.stored_rules()!r}",
        )

    def test_revoke_narrows_listing_and_persists_on_reopen(self):
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("editor", PERMISSION_READ).check_returncode()

        # 撤销 editor 的读取授权：反查立即只剩 reader。
        revoke_proc = self.revoke("editor", PERMISSION_READ)
        self.assertEqual(
            revoke_proc.returncode,
            0,
            f"撤销准备失败：stdout={revoke_proc.stdout!r}，"
            f"stderr={revoke_proc.stderr!r}",
        )

        proc = self.list_permission_roles(PERMISSION_READ)
        self.assert_listing_equals(proc, PERMISSION_READ, ["reader"])

        # 每次调用都重新打开同一规则库：撤销后的收窄结果必须持久化。
        reopened_proc = self.list_permission_roles(PERMISSION_READ)
        self.assert_listing_equals(reopened_proc, PERMISSION_READ, ["reader"])
        self.assertEqual(
            reopened_proc.stdout,
            proc.stdout,
            f"重新打开同一规则库后结果应一致，首次 {proc.stdout!r}，"
            f"重开后 {reopened_proc.stdout!r}",
        )

    def test_never_granted_or_fully_revoked_permission_returns_empty_roles(self):
        # 从未授予的权限：空角色数组。
        self.assert_listing_equals(
            self.list_permission_roles(PERMISSION_READ), PERMISSION_READ, []
        )

        # 授予后全部撤销：同样返回空角色数组。
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.revoke("reader", PERMISSION_READ).check_returncode()
        self.assert_listing_equals(
            self.list_permission_roles(PERMISSION_READ), PERMISSION_READ, []
        )

    def test_roles_deduped_and_sorted_by_unicode_codepoint(self):
        # 重复授予同一（角色, 权限）不产生重复项；角色按码点升序。
        for role in ("中", "a", "A", "reader"):
            self.grant(role, PERMISSION_READ).check_returncode()
        self.grant("reader", PERMISSION_READ).check_returncode()

        proc = self.list_permission_roles(PERMISSION_READ)
        result = self.assert_success_role_listing(proc, PERMISSION_READ)
        # Unicode 码点升序：A(0x41) < a(0x61) < reader < 中(0x4E2D)。
        self.assertEqual(
            result["roles"],
            ["A", "a", "reader", "中"],
            f"角色应去重并按 Unicode 码点升序排列，实际为 {result['roles']!r}",
        )

    def test_permission_name_surrounding_whitespace_is_trimmed(self):
        self.grant("reader", PERMISSION_READ).check_returncode()

        # 带首尾空白的权限名规整后匹配；输出使用规整后的权限。
        proc = self.list_permission_roles("\t documents:read \n")
        result = self.assert_success_role_listing(proc, "\t documents:read \n")
        self.assertEqual(
            result["permission"],
            PERMISSION_READ,
            f"输出权限应为规整后的 {PERMISSION_READ}，实际为 {result['permission']!r}",
        )
        self.assertEqual(
            result,
            {"permission": PERMISSION_READ, "roles": ["reader"]},
            f"带空白权限名的反查结果与预期不符，实际为 {result!r}",
        )

    def test_wildcard_like_characters_match_literally(self):
        # 星号、百分号、下划线按普通字符处理：完整名称大小写敏感精确匹配。
        self.grant("reader", "documents:*").check_returncode()
        self.grant("editor", "doc_%_read").check_returncode()

        self.assert_listing_equals(
            self.list_permission_roles("documents:*"), "documents:*", ["reader"]
        )
        self.assert_listing_equals(
            self.list_permission_roles("doc_%_read"), "doc_%_read", ["editor"]
        )
        # 不做模式匹配：documents:read 与 documents:* 互不相干。
        self.assert_listing_equals(
            self.list_permission_roles(PERMISSION_READ), PERMISSION_READ, []
        )

    def test_query_is_read_only(self):
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("reader", PERMISSION_WRITE).check_returncode()
        self.grant("editor", PERMISSION_READ).check_returncode()
        rules_before = self.stored_rules()

        for permission in (PERMISSION_READ, PERMISSION_EXPORT, "  documents:read\t"):
            with self.subTest(permission=permission):
                proc = self.list_permission_roles(permission)
                self.assert_success_role_listing(proc, permission)

        self.assertEqual(
            self.stored_rules(),
            rules_before,
            f"按权限反查应为只读：查询前 {rules_before!r}，"
            f"查询后 {self.stored_rules()!r}",
        )

    def test_missing_db_with_existing_parent_is_created_and_usable(self):
        self.assertFalse(
            os.path.exists(self.db_path), "测试前置：规则库文件应尚未创建"
        )

        # 父目录已存在而文件不存在：查询应创建可用空库并返回空角色数组。
        proc = self.list_permission_roles(PERMISSION_READ)
        self.assert_listing_equals(proc, PERMISSION_READ, [])
        self.assertTrue(
            os.path.exists(self.db_path),
            "父目录存在时查询应创建规则库文件",
        )

        # 创建出的库必须可用：授权后再次查询即可看到角色。
        self.grant("reader", PERMISSION_READ).check_returncode()
        followup = self.list_permission_roles(PERMISSION_READ)
        self.assert_listing_equals(followup, PERMISSION_READ, ["reader"])

    # ---- 错误边界 -------------------------------------------------------

    def test_empty_or_blank_permission_is_invalid_and_creates_no_database(self):
        for index, permission in enumerate(("", "   ", "\t \n")):
            with self.subTest(permission=permission):
                fresh_db = os.path.join(self.tmpdir, f"perm_invalid_{index}.db")
                argv = ("list-permission-roles", permission)
                proc = self.run_rbac(*argv, db=fresh_db)
                self.assert_invalid_name(proc, argv, fresh_db_path=fresh_db)

    def test_invalid_permission_does_not_change_existing_grants(self):
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("editor", PERMISSION_EXPORT).check_returncode()
        rules_before = self.stored_rules()

        for permission in ("", "   ", "\t\n "):
            with self.subTest(permission=permission):
                argv = ("list-permission-roles", permission)
                self.assert_invalid_name(self.run_rbac(*argv), argv)

        self.assertEqual(
            self.stored_rules(),
            rules_before,
            f"非法权限查询不应改变已有授权，之前 {rules_before!r}，"
            f"之后 {self.stored_rules()!r}",
        )

    def test_invalid_name_takes_precedence_over_missing_parent_directory(self):
        # 即使数据库父目录不存在，空权限也必须优先判定 invalid_name，
        # 且全程不触碰存储（不创建父目录或数据库文件）。
        missing_parent_db = os.path.join(self.tmpdir, "missing_dir", "rules.db")
        argv = ("list-permission-roles", " ")
        proc = self.run_rbac(*argv, db=missing_parent_db)
        self.assert_invalid_name(proc, argv, fresh_db_path=missing_parent_db)
        self.assertFalse(
            os.path.exists(os.path.dirname(missing_parent_db)),
            f"输入 {argv!r}：invalid_name 不应创建父目录，"
            f"实际存在 {os.path.dirname(missing_parent_db)!r}",
        )

    def test_valid_permission_with_missing_parent_directory_is_storage_error(self):
        missing_parent_db = os.path.join(self.tmpdir, "missing_dir", "rules.db")
        self.assertFalse(
            os.path.exists(os.path.dirname(missing_parent_db)),
            "测试前置：父目录应不存在",
        )

        argv = ("list-permission-roles", PERMISSION_READ)
        proc = self.run_rbac(*argv, db=missing_parent_db)
        self.assert_storage_error(proc, argv)

        # 不得夹带任何成功结果或异常堆栈。
        self.assertNotIn(
            "roles",
            proc.stdout,
            f"输入 {argv!r}：存储失败不得输出成功结果，实际为 {proc.stdout!r}",
        )
        self.assertNotIn(
            "Traceback",
            proc.stderr,
            f"输入 {argv!r}：标准错误不得包含异常堆栈，实际为 {proc.stderr!r}",
        )


if __name__ == "__main__":
    unittest.main()
