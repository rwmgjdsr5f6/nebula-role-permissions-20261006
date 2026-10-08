"""check --explain 实际授权来源（granted_roles）的回归测试。

通过三种层面核对新增的可选 --explain 开关：

1. `python -m rbac` 子进程走完整公开命令行入口（CheckExplainTests）：
   - 不带 --explain 时 check 输出仍只含 member、permission、roles、
     allowed、reason 五个字段，与既有形态逐字节一致；
   - 带 --explain 时仅额外增加 granted_roles 字符串数组，含该成员固定
     绑定且确实直接获授请求权限的角色，去重后按完整角色名的 Unicode
     码点升序排列；roles 仍表示全部固定角色，保留原顺序与重复项；
   - 固定验收关系 alice -> reader：授权后 allowed=true、
     reason="直接角色授权"、roles 与 granted_roles 均为 ["reader"]；
     即使同库 editor 也获授该权限，来源仍只有 reader；撤销 reader 的
     授权后 allowed=false、reason="权限未授予"、granted_roles=[]，
     roles 仍为 ["reader"]；bob 与大小写不同的 Alice 均以“成员未配置”
     拒绝，roles 与 granted_roles 都为空；
   - 正常允许与拒绝均退出 0、标准错误为空、标准输出为一行带末尾换行
     的 UTF-8 JSON；查询只读，缺文件且父目录可写时仍创建空库；
   - 名称仍只去除首尾空白、按大小写敏感的完整字符串匹配，内部空白与
     "*"、"%"、"_" 不作特殊解释；空成员名或空权限名退出 2，stderr 为
     {"error":"invalid_name"}，且不打开或创建数据库；
   - 父目录不存在、非 SQLite 文件等存储失败退出 1、stdout 为空、stderr
     为 {"error":"storage_error"}；已有规则表缺少 permission 列时
     alice 查询报存储错误，bob 保留未配置成员的正常拒绝。

2. store 层直接单元核对（ListGrantedRolesForPermissionStoreTests）：
   多角色来源的去重、码点排序、范围隔离、空角色短路与缺列存储失败，
   这些情形无法经只有 alice -> reader 的公开命令行构造。

3. policy.decide 的纯计算核对（DecideGrantedRoleAnnotationTests）：
   granted_roles 仅在显式传入时追加，且不参与 allowed/reason 决定，
   返回的 roles 与 granted_roles 均为独立副本。

只依赖 Python 3 标准库与 SQLite；每个命令行用例使用独立临时目录，
结束后自动清理。从项目根目录执行：

    python -m unittest discover -s tests -p test_check_explain.py
"""

import copy
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest

# tests/ 的上一级即项目根目录（rbac 包所在目录）。
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from rbac import policy, store  # noqa: E402  （sys.path 准备后再导入项目包）

PERMISSION_READ = "documents:read"
PERMISSION_WRITE = "documents:write"
INVALID_NAME_ERROR = '{"error":"invalid_name"}\n'
STORAGE_ERROR = '{"error":"storage_error"}\n'

# 不兼容的表结构：只有 role 列，缺少 permission 列。
_INCOMPATIBLE_SCHEMA = "CREATE TABLE role_permissions (role TEXT)"

# 带开关各结果的紧凑 UTF-8 JSON 逐字形态（末尾均恰有一个换行）。
ALICE_ALLOWED_EXPLAIN = (
    '{"member":"alice","permission":"documents:read","roles":["reader"],'
    '"allowed":true,"reason":"直接角色授权","granted_roles":["reader"]}\n'
)
ALICE_NOT_GRANTED_EXPLAIN = (
    '{"member":"alice","permission":"documents:read","roles":["reader"],'
    '"allowed":false,"reason":"权限未授予","granted_roles":[]}\n'
)
BOB_NOT_CONFIGURED_EXPLAIN = (
    '{"member":"bob","permission":"documents:read","roles":[],'
    '"allowed":false,"reason":"成员未配置","granted_roles":[]}\n'
)


class CheckExplainTests(unittest.TestCase):
    """通过 `python -m rbac` 子进程核对 check --explain 的对外行为。"""

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

    def check_explain(self, member, permission=PERMISSION_READ):
        return self.run_rbac("check", member, permission, "--explain")

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
        self.assertEqual(
            proc.stderr,
            STORAGE_ERROR,
            f"输入 {argv!r}：标准错误应恰为 {STORAGE_ERROR!r}，"
            f"实际为 {proc.stderr!r}",
        )

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
            self.assertFalse(
                os.path.exists(fresh_db_path),
                f"输入 {argv!r}：空名称不应创建数据库文件 {fresh_db_path}",
            )

    def stored_rules(self):
        """直接读取 SQLite，返回排序后的 (role, permission) 授权记录。"""
        with sqlite3.connect(self.db_path) as conn:
            return sorted(
                conn.execute(
                    "SELECT role, permission FROM role_permissions"
                ).fetchall()
            )

    # ---- 固定验收主流程 --------------------------------------------------

    def test_acceptance_grant_then_check_alice_explain(self):
        self.grant("reader", PERMISSION_READ).check_returncode()

        argv = ("check", "alice", PERMISSION_READ, "--explain")
        proc = self.run_rbac(*argv)
        result = self.assert_success(proc, argv)

        # 允许、原因、两个角色数组均按验收口径取值。
        self.assertEqual(
            result,
            {
                "member": "alice",
                "permission": PERMISSION_READ,
                "roles": ["reader"],
                "allowed": True,
                "reason": "直接角色授权",
                "granted_roles": ["reader"],
            },
            f"授权后 check --explain 结果与验收口径不符，实际为 {result!r}",
        )
        self.assertEqual(
            set(result.keys()),
            {"member", "permission", "roles", "allowed", "reason", "granted_roles"},
            f"带开关应恰为六个字段，实际为 {set(result.keys())}",
        )
        # 紧凑 UTF-8 JSON 的逐字形态：granted_roles 排在 reason 之后。
        self.assertEqual(proc.stdout, ALICE_ALLOWED_EXPLAIN)

    def test_editor_also_granted_does_not_enter_granted_roles(self):
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("editor", PERMISSION_READ).check_returncode()

        argv = ("check", "alice", PERMISSION_READ, "--explain")
        proc = self.run_rbac(*argv)
        result = self.assert_success(proc, argv)

        # alice 只固定绑定 reader：即使 editor 同获授该权限，
        # granted_roles 仍只有 reader；这是来源隔离而非授权未写入。
        self.assertEqual(result["roles"], ["reader"])
        self.assertTrue(result["allowed"])
        self.assertEqual(result["granted_roles"], ["reader"])
        self.assertNotIn("editor", result["granted_roles"])
        self.assertEqual(self.stored_rules(),
                         [("editor", PERMISSION_READ), ("reader", PERMISSION_READ)])

    def test_revoke_reader_leaves_empty_granted_roles_but_role_remains(self):
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("editor", PERMISSION_READ).check_returncode()
        self.revoke("reader", PERMISSION_READ).check_returncode()

        argv = ("check", "alice", PERMISSION_READ, "--explain")
        proc = self.run_rbac(*argv)
        result = self.assert_success(proc, argv)

        self.assertFalse(result["allowed"])
        self.assertEqual(result["reason"], "权限未授予")
        self.assertEqual(result["granted_roles"], [])
        # roles 仍是全部固定角色：撤销授权不改变固定成员关系。
        self.assertEqual(result["roles"], ["reader"])
        self.assertEqual(proc.stdout, ALICE_NOT_GRANTED_EXPLAIN)
        # editor 的授权仍在库中，只是与 alice 无关，不能作为来源。
        self.assertEqual(self.stored_rules(), [("editor", PERMISSION_READ)])

    def test_unconfigured_members_have_both_role_arrays_empty(self):
        self.grant("reader", PERMISSION_READ).check_returncode()
        for member in ("bob", "Alice"):
            with self.subTest(member=member):
                argv = ("check", member, PERMISSION_READ, "--explain")
                proc = self.run_rbac(*argv)
                result = self.assert_success(proc, argv)
                self.assertEqual(
                    result,
                    {
                        "member": member,
                        "permission": PERMISSION_READ,
                        "roles": [],
                        "allowed": False,
                        "reason": "成员未配置",
                        "granted_roles": [],
                    },
                    f"未配置成员 {member!r} 应以成员未配置拒绝且两个角色"
                    f"数组都为空，实际为 {result!r}",
                )
        # bob 的逐字形态。
        self.assertEqual(
            self.run_rbac("check", "bob", PERMISSION_READ, "--explain").stdout,
            BOB_NOT_CONFIGURED_EXPLAIN,
        )

    def test_flag_position_before_permission_is_equivalent(self):
        self.grant("reader", PERMISSION_READ).check_returncode()
        argv = ("check", "alice", "--explain", PERMISSION_READ)
        proc = self.run_rbac(*argv)
        result = self.assert_success(proc, argv)
        self.assertEqual(result["granted_roles"], ["reader"])
        self.assertTrue(result["allowed"])

    # ---- 不带开关保持原样 ------------------------------------------------

    def test_check_without_explain_keeps_five_fields(self):
        self.grant("reader", PERMISSION_READ).check_returncode()

        argv = ("check", "alice", PERMISSION_READ)
        proc = self.run_rbac(*argv)
        result = self.assert_success(proc, argv)
        self.assertEqual(
            set(result.keys()),
            {"member", "permission", "roles", "allowed", "reason"},
            f"不带开关不应出现 granted_roles，实际键为 {set(result.keys())}",
        )
        self.assertEqual(
            proc.stdout,
            '{"member":"alice","permission":"documents:read",'
            '"roles":["reader"],"allowed":true,"reason":"直接角色授权"}\n',
            f"不带开关的字节形态应与既有形态一致，实际为 {proc.stdout!r}",
        )

    def test_check_without_explain_denials_unchanged(self):
        # 权限未授予与成员未配置两种拒绝在不带开关时均不增字段。
        not_granted = self.assert_success(
            self.run_rbac("check", "alice", PERMISSION_WRITE),
            ("check", "alice", PERMISSION_WRITE),
        )
        self.assertEqual(
            set(not_granted.keys()),
            {"member", "permission", "roles", "allowed", "reason"},
        )
        not_configured = self.assert_success(
            self.run_rbac("check", "bob", PERMISSION_READ),
            ("check", "bob", PERMISSION_READ),
        )
        self.assertEqual(
            set(not_configured.keys()),
            {"member", "permission", "roles", "allowed", "reason"},
        )

    # ---- 空库、只读与名称语义 --------------------------------------------

    def test_empty_rulebase_explain_creates_db_and_denies_with_empty_sources(self):
        # 文件缺失且父目录可写：查询初始化空库；alice 有 reader 角色但无授权。
        self.assertFalse(os.path.exists(self.db_path), "测试前置：数据库应尚未创建")
        argv = ("check", "alice", PERMISSION_READ, "--explain")
        proc = self.run_rbac(*argv)
        result = self.assert_success(proc, argv)
        self.assertEqual(
            result,
            {
                "member": "alice",
                "permission": PERMISSION_READ,
                "roles": ["reader"],
                "allowed": False,
                "reason": "权限未授予",
                "granted_roles": [],
            },
        )
        self.assertTrue(os.path.exists(self.db_path), "缺文件查询应沿用建库行为")

    def test_explain_is_read_only(self):
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("editor", PERMISSION_WRITE).check_returncode()
        rules_before = self.stored_rules()

        for member, permission in (
            ("alice", PERMISSION_READ),
            ("alice", PERMISSION_WRITE),
            ("bob", PERMISSION_READ),
            ("Alice", PERMISSION_READ),
        ):
            self.assert_success(
                self.run_rbac("check", member, permission, "--explain"),
                ("check", member, permission, "--explain"),
            )

        self.assertEqual(
            self.stored_rules(),
            rules_before,
            "check --explain 应为只读，不应改动授权记录",
        )

    def test_surrounding_whitespace_trimmed_and_matched_exactly(self):
        self.grant("reader", PERMISSION_READ).check_returncode()

        trimmed = self.assert_success(
            self.run_rbac("check", "\t alice \n", f" {PERMISSION_READ}\n", "--explain"),
            ("check", "whitespace-padded", "whitespace-padded", "--explain"),
        )
        self.assertEqual(trimmed["member"], "alice")
        self.assertEqual(trimmed["permission"], PERMISSION_READ)
        self.assertEqual(trimmed["granted_roles"], ["reader"])

        # 大小写不同的权限不命中：有角色但权限未授予，来源为空。
        wrong_case = self.assert_success(
            self.run_rbac("check", "alice", "documents:Read", "--explain"),
            ("check", "alice", "documents:Read", "--explain"),
        )
        self.assertEqual(wrong_case["allowed"], False)
        self.assertEqual(wrong_case["reason"], "权限未授予")
        self.assertEqual(wrong_case["granted_roles"], [])

    def test_special_characters_in_permission_are_literal(self):
        # 内部空白与 "*"、"%"、"_" 均为普通字符：必须显式授予才成为来源。
        for permission in ("Doc Read", "documents:*", "documents:%", "a_b"):
            self.grant("reader", permission).check_returncode()
        for permission in ("Doc Read", "documents:*", "documents:%", "a_b"):
            with self.subTest(permission=permission):
                result = self.assert_success(
                    self.check_explain("alice", permission),
                    ("check", "alice", permission, "--explain"),
                )
                self.assertTrue(result["allowed"])
                self.assertEqual(result["granted_roles"], ["reader"])
        # 未显式授予的通配形态不命中 documents:read。
        self.assertEqual(
            self.assert_success(
                self.check_explain("alice", "documents:other"),
                ("check", "alice", "documents:other", "--explain"),
            )["granted_roles"],
            [],
        )

    # ---- 名称与存储边界 --------------------------------------------------

    def test_blank_names_are_invalid_and_create_no_database(self):
        cases = [
            ("check", "", PERMISSION_READ, "--explain"),
            ("check", "alice", "", "--explain"),
            ("check", "   ", PERMISSION_READ, "--explain"),
            ("check", "alice", "\t \n", "--explain"),
        ]
        for index, argv in enumerate(cases):
            with self.subTest(argv=argv):
                fresh_db = os.path.join(self.tmpdir, f"explain_invalid_{index}.db")
                self.assert_invalid_name(
                    self.run_rbac(*argv, db=fresh_db), argv, fresh_db_path=fresh_db
                )

    def test_invalid_name_takes_precedence_over_storage_error(self):
        missing_parent_db = os.path.join(self.tmpdir, "missing_dir", "rules.db")
        argv = ("check", " ", "", "--explain")
        self.assert_invalid_name(
            self.run_rbac(*argv, db=missing_parent_db),
            argv,
            fresh_db_path=missing_parent_db,
        )

    def test_missing_parent_directory_is_storage_error(self):
        missing_parent_db = os.path.join(self.tmpdir, "missing_dir", "rules.db")
        # 连接建立先于角色读取：即使查询无角色的 bob 也是存储失败。
        for member in ("alice", "bob"):
            argv = ("check", member, PERMISSION_READ, "--explain")
            self.assert_storage_error(
                self.run_rbac(*argv, db=missing_parent_db), argv
            )

    def test_non_sqlite_file_is_storage_error_even_for_bob(self):
        non_sqlite = os.path.join(self.tmpdir, "notsqlite.db")
        with open(non_sqlite, "wb") as handle:
            handle.write(b"x" * 128)
        argv = ("check", "bob", PERMISSION_READ, "--explain")
        self.assert_storage_error(self.run_rbac(*argv, db=non_sqlite), argv)
        # 失败不修补文件：仍是那 128 个 x。
        with open(non_sqlite, "rb") as handle:
            self.assertEqual(handle.read(), b"x" * 128)

    def test_missing_permission_column_alice_error_bob_normal_rejection(self):
        # 已有表缺 permission 列：alice 必须查规则表 -> 存储错误；
        # bob 角色为空 -> 不触碰规则表，仍按成员未配置正常拒绝；不补列。
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(_INCOMPATIBLE_SCHEMA)
            conn.execute("INSERT INTO role_permissions (role) VALUES ('reader')")

        argv_alice = ("check", "alice", PERMISSION_READ, "--explain")
        self.assert_storage_error(self.run_rbac(*argv_alice), argv_alice)

        argv_bob = ("check", "bob", PERMISSION_READ, "--explain")
        proc = self.run_rbac(*argv_bob)
        result = self.assert_success(proc, argv_bob)
        self.assertEqual(
            result,
            {
                "member": "bob",
                "permission": PERMISSION_READ,
                "roles": [],
                "allowed": False,
                "reason": "成员未配置",
                "granted_roles": [],
            },
        )
        self.assertEqual(proc.stdout, BOB_NOT_CONFIGURED_EXPLAIN)

        # 不修补结构：列仍只有 role，reader 行仍在。
        with sqlite3.connect(self.db_path) as conn:
            columns = [
                row[1]
                for row in conn.execute(
                    "PRAGMA table_info(role_permissions)"
                ).fetchall()
            ]
            rows = conn.execute("SELECT role FROM role_permissions").fetchall()
        self.assertEqual(columns, ["role"])
        self.assertEqual(rows, [("reader",)])


class ListGrantedRolesForPermissionStoreTests(unittest.TestCase):
    """store.list_granted_roles_for_permission 的直接单元核对。

    多角色来源的去重、码点排序与范围隔离无法经只有 alice -> reader 的
    公开命令行构造，故在存储层直接构造。
    """

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.conn = store.connect(os.path.join(self._tmpdir.name, "rules.db"))
        self.addCleanup(self.conn.close)

    def grant(self, role, permission):
        self.conn.execute(
            "INSERT INTO role_permissions (role, permission) VALUES (?, ?)",
            (role, permission),
        )

    def test_scopes_to_input_roles_dedupes_and_sorts_by_codepoint(self):
        # reader、editor、auditor 在入参范围内且都获授 read；viewer 不在
        # 范围内，即使同获授该权限也不得出现在结果中。
        for role in ("reader", "editor", "auditor", "viewer"):
            self.grant(role, PERMISSION_READ)
        self.grant("editor", PERMISSION_WRITE)
        self.conn.commit()

        # 入参故意乱序并含重复：输出仍去重且按码点升序。
        result = store.list_granted_roles_for_permission(
            self.conn, ["reader", "editor", "reader", "auditor"], PERMISSION_READ
        )
        self.assertEqual(result, ["auditor", "editor", "reader"])

        # 另一项权限只有 editor 获授。
        self.assertEqual(
            store.list_granted_roles_for_permission(
                self.conn, ["reader", "editor", "auditor"], PERMISSION_WRITE
            ),
            ["editor"],
        )

        # viewer 的授权不泄漏到不含 viewer 的范围查询里。
        self.assertEqual(
            store.list_granted_roles_for_permission(
                self.conn, ["reader"], PERMISSION_READ
            ),
            ["reader"],
        )

    def test_no_grant_or_no_match_returns_empty(self):
        self.grant("viewer", PERMISSION_READ)
        self.conn.commit()
        self.assertEqual(
            store.list_granted_roles_for_permission(
                self.conn, ["reader"], PERMISSION_READ
            ),
            [],
        )
        # 空库/未授予权限。
        self.assertEqual(
            store.list_granted_roles_for_permission(
                self.conn, ["reader", "editor"], PERMISSION_WRITE
            ),
            [],
        )

    def test_empty_roles_short_circuits_without_querying(self):
        # 空角色直接返回空列表：缺列的表也不会触发查询错误。
        self.conn.execute("DROP TABLE role_permissions")
        self.conn.execute(_INCOMPATIBLE_SCHEMA)
        self.conn.commit()
        self.assertEqual(
            store.list_granted_roles_for_permission(
                self.conn, [], PERMISSION_READ
            ),
            [],
        )

    def test_missing_permission_column_raises_storage_error(self):
        self.conn.execute("DROP TABLE role_permissions")
        self.conn.execute(_INCOMPATIBLE_SCHEMA)
        self.conn.execute("INSERT INTO role_permissions (role) VALUES ('reader')")
        self.conn.commit()
        with self.assertRaises(store.StorageError):
            store.list_granted_roles_for_permission(
                self.conn, ["reader"], PERMISSION_READ
            )

    def test_matching_is_case_sensitive_and_special_chars_are_literal(self):
        for role in ("reader", "re*der", "re_der"):
            self.grant(role, PERMISSION_READ)
        self.conn.commit()
        # Reader 不命中 reader；通配形态角色名按普通字符精确匹配。
        self.assertEqual(
            store.list_granted_roles_for_permission(
                self.conn, ["Reader"], PERMISSION_READ
            ),
            [],
        )
        self.assertEqual(
            store.list_granted_roles_for_permission(
                self.conn, ["re%der"], PERMISSION_READ
            ),
            [],
        )
        self.assertEqual(
            store.list_granted_roles_for_permission(
                self.conn, ["re*der", "re_der", "reader"], PERMISSION_READ
            ),
            ["re*der", "re_der", "reader"],
        )

    def test_result_is_consistent_with_permission_granted(self):
        self.grant("reader", PERMISSION_READ)
        self.conn.commit()
        granted_roles = store.list_granted_roles_for_permission(
            self.conn, ["reader"], PERMISSION_READ
        )
        self.assertEqual(
            store.permission_granted(self.conn, ["reader"], PERMISSION_READ),
            bool(granted_roles),
        )
        ungranted = store.list_granted_roles_for_permission(
            self.conn, ["reader"], PERMISSION_WRITE
        )
        self.assertEqual(ungranted, [])
        self.assertFalse(
            store.permission_granted(self.conn, ["reader"], PERMISSION_WRITE)
        )


class DecideGrantedRoleAnnotationTests(unittest.TestCase):
    """policy.decide 的 granted_roles 追加行为（纯计算，不访问存储）。"""

    def setUp(self):
        # 快照原配置并替换为合成配置，addCleanup 保证恢复。
        self._original_member_roles = copy.deepcopy(policy.FIXED_MEMBER_ROLES)
        policy.FIXED_MEMBER_ROLES.clear()
        policy.FIXED_MEMBER_ROLES.update(
            {"alice": ("reader", "editor", "reader")}
        )
        self.addCleanup(self._restore_member_roles)

    def _restore_member_roles(self):
        policy.FIXED_MEMBER_ROLES.clear()
        policy.FIXED_MEMBER_ROLES.update(self._original_member_roles)

    def test_without_granted_roles_keeps_five_keys(self):
        result = policy.decide("alice", PERMISSION_READ, True)
        self.assertEqual(
            set(result.keys()),
            {"member", "permission", "roles", "allowed", "reason"},
        )

    def test_granted_roles_appended_only_when_given(self):
        roles = ["reader", "editor", "reader"]
        result = policy.decide(
            "alice", PERMISSION_READ, True, roles=roles,
            granted_roles=["editor", "reader"],
        )
        # roles 保留原顺序与重复项；granted_roles 为传入的已排序去重列表。
        self.assertEqual(result["roles"], ["reader", "editor", "reader"])
        self.assertEqual(result["granted_roles"], ["editor", "reader"])
        self.assertEqual(
            set(result.keys()),
            {"member", "permission", "roles", "allowed", "reason", "granted_roles"},
        )

    def test_empty_list_is_an_explicit_annotation(self):
        # 显式传入空列表（撤销后 / 未配置成员路径）也要带字段。
        result = policy.decide(
            "bob", PERMISSION_READ, False, roles=[], granted_roles=[]
        )
        self.assertEqual(result["granted_roles"], [])
        self.assertEqual(result["roles"], [])
        self.assertEqual(result["reason"], "成员未配置")

    def test_granted_roles_does_not_drive_decision(self):
        # allowed/reason 只由 granted 决定；来源字段仅作说明。
        result = policy.decide(
            "alice", PERMISSION_READ, False,
            granted_roles=["reader"],
        )
        self.assertFalse(result["allowed"])
        self.assertEqual(result["reason"], "权限未授予")
        self.assertEqual(result["granted_roles"], ["reader"])

    def test_returned_role_lists_are_independent_copies(self):
        source_roles = ["reader", "editor"]
        result = policy.decide(
            "alice", PERMISSION_READ, True,
            roles=source_roles, granted_roles=source_roles,
        )
        result["roles"].append("administrator")
        result["granted_roles"].append("administrator")
        self.assertEqual(source_roles, ["reader", "editor"])
        again = policy.decide(
            "alice", PERMISSION_READ, True,
            roles=source_roles, granted_roles=["editor", "reader"],
        )
        self.assertEqual(again["granted_roles"], ["editor", "reader"])


if __name__ == "__main__":
    unittest.main()
