"""list-member-permissions --explain 授权来源说明的命令行回归测试。

只依赖 Python 3 标准库；每个用例使用独立临时数据库目录，结束后自动清理。
从项目根目录执行：

    python -m unittest discover -s tests

通过 `python -m rbac` 子进程走完整公开命令行入口，覆盖范围：
- 不带 --explain 时输出仍只含 member、roles、permissions 三个字段，
  与既有形态完全一致；
- 带 --explain 时仅额外增加 sources 数组；sources 与 permissions
  一一对应，每项只含 permission 和 roles；来源角色只包含成员固定绑定
  且确实获授对应权限的角色（editor 同样获授 documents:read 也不出现），
  不出现空来源项；
- 撤销固定角色的授权后，permissions 与 sources 同时为空，roles 仍保留
  固定角色；未配置成员 bob 与大小写不同的 Alice 返回空 roles、
  permissions、sources；
- 权限与来源角色按保存值原样保留（大小写、内部空白，"*"、"%"、"_"
  均为普通字符），去重并按完整名称的 Unicode 码点升序排列；
- 查询只读，调用前后全部授权记录一致；
- 名称校验与存储边界沿用既有约定：空名退出码 2 且不建库，父目录缺失
  退出码 1，非 SQLite 文件退出码 1；缺 permission 列的已有表上
  alice 为存储错误、bob 仍成功并带空 sources，不修补表结构。

多角色重叠获授同一项权限时的来源聚合无法经公开命令行构造（固定配置中
当前只有 alice -> reader），故该情形在 store 层直接做只读单元核对。
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
sys.path.insert(0, PROJECT_ROOT)

from rbac import store  # noqa: E402  （sys.path 准备后再导入项目包）

PERMISSION_READ = "documents:read"
PERMISSION_WRITE = "documents:write"
INVALID_NAME_ERROR = '{"error":"invalid_name"}\n'
STORAGE_ERROR = '{"error":"storage_error"}\n'

# 不兼容的表结构：只有 role 列，缺少 permission 列。
_INCOMPATIBLE_SCHEMA = "CREATE TABLE role_permissions (role TEXT)"


class ListMemberPermissionsExplainTests(unittest.TestCase):
    """通过 `python -m rbac` 子进程核对 --explain 的对外行为。"""

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

    def grant(self, role, permission):
        return self.run_rbac("grant", role, permission)

    def revoke(self, role, permission):
        return self.run_rbac("revoke", role, permission)

    def explain(self, member):
        return self.run_rbac("list-member-permissions", member, "--explain")

    def assert_success(self, proc, argv):
        """退出码 0、stderr 为空、stdout 恰为一个 JSON 对象加换行。"""
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
            proc.stdout.count("\n"),
            1,
            f"输入 {argv!r}：标准输出应只有一个 JSON 对象加换行，"
            f"实际为 {proc.stdout!r}",
        )
        self.assertTrue(
            proc.stdout.endswith("\n"),
            f"输入 {argv!r}：标准输出应以换行结束，实际为 {proc.stdout!r}",
        )
        return json.loads(proc.stdout[:-1])

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
            f"输入 {argv!r}：storage_error 时标准输出应为空，"
            f"实际为 {proc.stdout!r}",
        )
        self.assertEqual(proc.stderr, STORAGE_ERROR)

    def assert_invalid_name(self, proc, argv, fresh_db_path=None):
        """空名称/纯空白：退出码 2，stdout 为空，stderr 仅为固定错误行。"""
        self.assertEqual(
            proc.returncode,
            2,
            f"输入 {argv!r}：期望退出码 2，实际 {proc.returncode}，"
            f"stdout={proc.stdout!r}，stderr={proc.stderr!r}",
        )
        self.assertEqual(proc.stdout, "")
        self.assertEqual(proc.stderr, INVALID_NAME_ERROR)
        if fresh_db_path is not None:
            self.assertFalse(os.path.exists(fresh_db_path))

    def stored_rules(self):
        """直接读取 SQLite，返回排序后的 (role, permission) 授权记录。"""
        with sqlite3.connect(self.db_path) as conn:
            return sorted(
                conn.execute(
                    "SELECT role, permission FROM role_permissions"
                ).fetchall()
            )

    # ---- 主流程与字段形态 -----------------------------------------------

    def test_without_explain_keeps_three_fields(self):
        # 开关可选：不带 --explain 时字段与输出格式与原来完全一致。
        self.grant("reader", PERMISSION_READ).check_returncode()
        argv = ("list-member-permissions", "alice")
        proc = self.run_rbac(*argv)
        result = self.assert_success(proc, argv)
        self.assertEqual(
            set(result.keys()),
            {"member", "roles", "permissions"},
            f"不带 --explain 不应出现 sources，实际键为 {set(result.keys())}",
        )
        self.assertEqual(
            proc.stdout,
            '{"member":"alice","roles":["reader"],'
            '"permissions":["documents:read"]}\n',
            f"不带 --explain 的字节形态应与既有形态一致，"
            f"实际为 {proc.stdout!r}",
        )

    def test_explain_adds_only_sources_with_fixed_bound_roles(self):
        # reader 与 editor 各自获授 documents:read；alice 只固定绑定 reader。
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("editor", PERMISSION_READ).check_returncode()

        argv = ("list-member-permissions", "alice", "--explain")
        proc = self.run_rbac(*argv)
        result = self.assert_success(proc, argv)

        # 只在原有三字段上增加 sources；sources 项只含 permission、roles。
        self.assertEqual(set(result.keys()), {"member", "roles", "permissions", "sources"})
        self.assertEqual(result["member"], "alice")
        self.assertEqual(result["roles"], ["reader"])
        self.assertEqual(result["permissions"], [PERMISSION_READ])
        self.assertEqual(
            result["sources"],
            [{"permission": PERMISSION_READ, "roles": ["reader"]}],
            f"来源只能是 alice 固定绑定且确实获授该权限的 reader，"
            f"不得包含 editor，实际为 {result['sources']!r}",
        )
        for item in result["sources"]:
            self.assertEqual(
                set(item.keys()),
                {"permission", "roles"},
                f"sources 每项只含 permission 和 roles，实际为 {item!r}",
            )

        # 紧凑 UTF-8 JSON 的逐字形态。
        self.assertEqual(
            proc.stdout,
            '{"member":"alice","roles":["reader"],'
            '"permissions":["documents:read"],'
            '"sources":[{"permission":"documents:read",'
            '"roles":["reader"]}]}\n',
            f"--explain 字节形态与预期不符，实际为 {proc.stdout!r}",
        )

        # editor 的授权确实在库中：不含它是来源隔离，而非授权未写入。
        self.assertEqual(
            self.stored_rules(),
            [("editor", PERMISSION_READ), ("reader", PERMISSION_READ)],
        )

    def test_sources_correspond_one_to_one_with_permissions(self):
        # reader 获授两项权限：sources 与 permissions 必须一一对应，
        # 顺序一致，且不出现空来源项。
        self.grant("reader", PERMISSION_WRITE).check_returncode()
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("reader", PERMISSION_READ).check_returncode()

        result = self.assert_success(
            self.explain("alice"), ("list-member-permissions", "alice", "--explain")
        )
        self.assertEqual(
            result["permissions"], [PERMISSION_READ, PERMISSION_WRITE]
        )
        self.assertEqual(
            [item["permission"] for item in result["sources"]],
            result["permissions"],
            "sources 必须与 permissions 一一对应且顺序一致",
        )
        self.assertTrue(all(item["roles"] for item in result["sources"]),
                        "不得出现空来源项")
        self.assertEqual(
            result["sources"],
            [
                {"permission": PERMISSION_READ, "roles": ["reader"]},
                {"permission": PERMISSION_WRITE, "roles": ["reader"]},
            ],
        )

    def test_revoke_leaves_empty_permissions_and_sources_but_role_remains(self):
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("editor", PERMISSION_READ).check_returncode()
        self.revoke("reader", PERMISSION_READ).check_returncode()

        argv = ("list-member-permissions", "alice", "--explain")
        proc = self.run_rbac(*argv)
        result = self.assert_success(proc, argv)
        # 撤销 reader 的授权后：permissions、sources 均空，roles 仍为 reader；
        # editor 的授权与 alice 无关，不能作为来源。
        self.assertEqual(result["roles"], ["reader"])
        self.assertEqual(result["permissions"], [])
        self.assertEqual(result["sources"], [])
        self.assertEqual(
            proc.stdout,
            '{"member":"alice","roles":["reader"],'
            '"permissions":[],"sources":[]}\n',
        )
        # editor 的授权仍在库中。
        self.assertEqual(self.stored_rules(), [("editor", PERMISSION_READ)])

    def test_unconfigured_members_have_empty_roles_permissions_sources(self):
        self.grant("reader", PERMISSION_READ).check_returncode()
        for member in ("bob", "Alice"):
            with self.subTest(member=member):
                argv = ("list-member-permissions", member, "--explain")
                result = self.assert_success(self.run_rbac(*argv), argv)
                self.assertEqual(
                    result,
                    {"member": member, "roles": [], "permissions": [], "sources": []},
                    f"未配置成员 {member!r} 应返回空 roles/permissions/sources，"
                    f"实际为 {result!r}",
                )

    def test_empty_rulebase_explain_shape(self):
        # 查询本身建库：alice 仍有 reader 角色，permissions 与 sources 为空。
        argv = ("list-member-permissions", "alice", "--explain")
        proc = self.run_rbac(*argv)
        result = self.assert_success(proc, argv)
        self.assertEqual(
            result,
            {"member": "alice", "roles": ["reader"], "permissions": [], "sources": []},
        )
        self.assertTrue(os.path.exists(self.db_path))

    def test_permissions_sorted_by_unicode_codepoint(self):
        for permission in ("中", "a", "A", PERMISSION_READ):
            self.grant("reader", permission).check_returncode()

        result = self.assert_success(
            self.explain("alice"), ("list-member-permissions", "alice", "--explain")
        )
        # Unicode 码点升序：A(0x41) < a(0x61) < documents:read < 中(0x4E2D)。
        expected = ["A", "a", PERMISSION_READ, "中"]
        self.assertEqual(result["permissions"], expected)
        self.assertEqual(
            [item["permission"] for item in result["sources"]],
            expected,
            "sources 顺序必须跟随 permissions 的码点升序",
        )

    def test_names_preserved_verbatim_case_and_special_chars(self):
        # 大小写、内部空白原样保留；"*"、"%"、"_" 均为普通字符。
        for permission in ("Doc Read", "a*b", "a%b", "a_b", "A"):
            self.grant("reader", permission).check_returncode()

        result = self.assert_success(
            self.explain("alice"), ("list-member-permissions", "alice", "--explain")
        )
        # Python 字符串排序即 Unicode 码点序：
        # "A" < "Doc Read" < "a*b"(0x2A) < "a%b"(0x25)...
        expected = ["A", "Doc Read", "a%b", "a*b", "a_b"]
        self.assertEqual(result["permissions"], expected)
        for item, permission in zip(result["sources"], expected):
            self.assertEqual(item, {"permission": permission, "roles": ["reader"]})

    def test_member_name_surrounding_whitespace_is_trimmed(self):
        self.grant("reader", PERMISSION_READ).check_returncode()
        argv = ("list-member-permissions", "\t alice \n", "--explain")
        result = self.assert_success(self.run_rbac(*argv), argv)
        self.assertEqual(
            result,
            {
                "member": "alice",
                "roles": ["reader"],
                "permissions": [PERMISSION_READ],
                "sources": [
                    {"permission": PERMISSION_READ, "roles": ["reader"]}
                ],
            },
        )

    def test_explain_is_read_only(self):
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("editor", PERMISSION_WRITE).check_returncode()
        rules_before = self.stored_rules()

        for member in ("alice", "bob", "Alice", "  alice\t"):
            with self.subTest(member=member):
                self.assert_success(
                    self.explain(member),
                    ("list-member-permissions", member, "--explain"),
                )

        self.assertEqual(
            self.stored_rules(),
            rules_before,
            "--explain 查询应为只读",
        )

    # ---- 名称与存储边界 --------------------------------------------------

    def test_blank_member_is_invalid_and_creates_no_database(self):
        for index, member in enumerate(("", "   ", "\t \n")):
            with self.subTest(member=member):
                fresh_db = os.path.join(self.tmpdir, f"explain_invalid_{index}.db")
                argv = ("list-member-permissions", member, "--explain")
                self.assert_invalid_name(
                    self.run_rbac(*argv, db=fresh_db), argv, fresh_db_path=fresh_db
                )

    def test_missing_parent_directory_is_storage_error(self):
        missing_parent_db = os.path.join(self.tmpdir, "missing_dir", "rules.db")
        argv = ("list-member-permissions", "alice", "--explain")
        self.assert_storage_error(
            self.run_rbac(*argv, db=missing_parent_db), argv
        )

    def test_non_sqlite_file_is_storage_error_even_for_bob(self):
        non_sqlite = os.path.join(self.tmpdir, "notsqlite.db")
        with open(non_sqlite, "wb") as handle:
            handle.write(b"x" * 128)
        argv = ("list-member-permissions", "bob", "--explain")
        self.assert_storage_error(self.run_rbac(*argv, db=non_sqlite), argv)
        # 失败不修补文件：仍是那 128 个 x。
        with open(non_sqlite, "rb") as handle:
            self.assertEqual(handle.read(), b"x" * 128)

    def test_missing_permission_column_alice_error_bob_empty_sources(self):
        # 已有表缺 permission 列：alice 必须查规则表 -> 存储错误；
        # bob 角色为空 -> 不触碰规则表，仍成功并带空 sources；不修补结构。
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(_INCOMPATIBLE_SCHEMA)
            conn.execute("INSERT INTO role_permissions (role) VALUES ('reader')")

        argv_alice = ("list-member-permissions", "alice", "--explain")
        self.assert_storage_error(self.run_rbac(*argv_alice), argv_alice)

        argv_bob = ("list-member-permissions", "bob", "--explain")
        proc = self.run_rbac(*argv_bob)
        result = self.assert_success(proc, argv_bob)
        self.assertEqual(
            result,
            {"member": "bob", "roles": [], "permissions": [], "sources": []},
        )
        self.assertEqual(
            proc.stdout,
            '{"member":"bob","roles":[],"permissions":[],"sources":[]}\n',
        )

        # 不修补结构：列仍只有 role，reader 行仍在。
        with sqlite3.connect(self.db_path) as conn:
            columns = [
                row[1]
                for row in conn.execute("PRAGMA table_info(role_permissions)").fetchall()
            ]
            rows = conn.execute("SELECT role FROM role_permissions").fetchall()
        self.assertEqual(columns, ["role"])
        self.assertEqual(rows, [("reader",)])


class PermissionRolesForRolesStoreTests(unittest.TestCase):
    """store 层多角色来源聚合的直接单元核对（公开固定配置无法构造该输入）。"""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.conn = store.connect(
            os.path.join(self._tmpdir.name, "rules.db")
        )
        self.addCleanup(self.conn.close)

    def test_overlapping_permissions_merge_dedup_and_sort_roles(self):
        # reader、editor、auditor 都在入参角色范围内；viewer 不在范围，
        # 即使获授同一权限也不得出现在来源中。
        for role, permission in (
            ("reader", PERMISSION_READ),
            ("editor", PERMISSION_READ),
            ("auditor", PERMISSION_READ),
            ("editor", PERMISSION_WRITE),
            ("viewer", PERMISSION_READ),
        ):
            self.conn.execute(
                "INSERT INTO role_permissions (role, permission) VALUES (?, ?)",
                (role, permission),
            )
        self.conn.commit()

        mapping = store.list_permission_roles_for_roles(
            self.conn, ["editor", "reader", "auditor"]
        )
        self.assertEqual(
            mapping,
            {
                PERMISSION_READ: ["auditor", "editor", "reader"],
                PERMISSION_WRITE: ["editor"],
            },
        )

    def test_empty_roles_short_circuits_without_querying(self):
        # 空角色直接返回空映射：缺列的表也不会触发查询错误。
        self.conn.execute("DROP TABLE role_permissions")
        self.conn.execute("CREATE TABLE role_permissions (role TEXT)")
        self.conn.commit()
        self.assertEqual(store.list_permission_roles_for_roles(self.conn, []), {})

    def test_roles_without_grants_yield_empty_mapping(self):
        self.conn.execute(
            "INSERT INTO role_permissions (role, permission) VALUES (?, ?)",
            ("viewer", PERMISSION_READ),
        )
        self.conn.commit()
        self.assertEqual(
            store.list_permission_roles_for_roles(self.conn, ["reader"]), {}
        )


if __name__ == "__main__":
    unittest.main()
