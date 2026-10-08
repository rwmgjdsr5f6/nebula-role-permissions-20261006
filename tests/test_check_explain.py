"""check --explain 实际授权来源（granted_roles）的命令行回归测试。

只依赖 Python 3 标准库；每个用例使用独立临时数据库目录，结束后自动清理。
从项目根目录执行：

    python -m unittest discover -s tests

通过 `python -m rbac` 子进程走完整公开命令行入口，覆盖范围：
- 不带 --explain 时输出仍只含 member、permission、roles、allowed、reason
  五个字段，与既有形态逐字节一致；
- 带 --explain 时仅额外增加 granted_roles 数组：只包含该成员固定绑定且
  确实直接获授请求权限的角色（editor 同样获授 documents:read 也不出现），
  去重后按完整角色名的 Unicode 码点升序排列；roles 仍表示全部固定角色；
- 撤销固定角色的对应授权后，allowed 为 false、reason 为“权限未授予”、
  granted_roles 为空，roles 仍保留固定角色；未配置成员 bob 与大小写不同
  的 Alice 两个角色数组都为空，reason 为“成员未配置”；
- 正常允许与拒绝均退出码 0、标准错误为空、标准输出为一行带末尾换行的
  UTF-8 JSON；查询只读，调用前后全部授权记录一致；
- 名称校验与存储边界沿用既有约定：空名退出码 2 且不建库，父目录缺失或
  非 SQLite 文件退出码 1；缺 permission 列的已有表上 alice 为存储错误、
  bob 仍按成员未配置正常拒绝，不修补表结构；文件缺失且父目录可写时
  查询仍创建空库。

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

    def check_explain(self, member, permission):
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

    def test_without_explain_keeps_five_fields(self):
        # 开关可选：不带 --explain 时字段与输出格式与原来完全一致。
        self.grant("reader", PERMISSION_READ).check_returncode()
        argv = ("check", "alice", PERMISSION_READ)
        proc = self.run_rbac(*argv)
        result = self.assert_success(proc, argv)
        self.assertEqual(
            set(result.keys()),
            {"member", "permission", "roles", "allowed", "reason"},
            f"不带 --explain 不应出现 granted_roles，实际键为 {set(result.keys())}",
        )
        self.assertEqual(
            proc.stdout,
            '{"member":"alice","permission":"documents:read",'
            '"roles":["reader"],"allowed":true,'
            '"reason":"直接角色授权"}\n',
            f"不带 --explain 的字节形态应与既有形态一致，"
            f"实际为 {proc.stdout!r}",
        )

    def test_explain_adds_only_granted_roles_with_fixed_bound_roles(self):
        # reader 与 editor 各自获授 documents:read；alice 只固定绑定 reader。
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("editor", PERMISSION_READ).check_returncode()

        argv = ("check", "alice", PERMISSION_READ, "--explain")
        proc = self.run_rbac(*argv)
        result = self.assert_success(proc, argv)

        # 只在原有五字段上增加 granted_roles。
        self.assertEqual(
            set(result.keys()),
            {"member", "permission", "roles", "allowed", "reason", "granted_roles"},
        )
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
            f"来源只能是 alice 固定绑定且确实获授该权限的 reader，"
            f"不得包含 editor，实际为 {result!r}",
        )

        # 紧凑 UTF-8 JSON 的逐字形态。
        self.assertEqual(
            proc.stdout,
            '{"member":"alice","permission":"documents:read",'
            '"roles":["reader"],"allowed":true,'
            '"reason":"直接角色授权","granted_roles":["reader"]}\n',
            f"--explain 字节形态与预期不符，实际为 {proc.stdout!r}",
        )

        # editor 的授权确实在库中：不含它是来源隔离，而非授权未写入。
        self.assertEqual(
            self.stored_rules(),
            [("editor", PERMISSION_READ), ("reader", PERMISSION_READ)],
        )

    def test_revoke_leaves_empty_granted_roles_but_role_remains(self):
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("editor", PERMISSION_READ).check_returncode()
        self.revoke("reader", PERMISSION_READ).check_returncode()

        argv = ("check", "alice", PERMISSION_READ, "--explain")
        proc = self.run_rbac(*argv)
        result = self.assert_success(proc, argv)
        # 撤销 reader 的授权后：allowed 为 false、granted_roles 为空，
        # roles 仍为 reader；editor 的授权与 alice 无关，不能作为来源。
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
            f"撤销后的解释结果与预期不符，实际为 {result!r}",
        )
        self.assertEqual(
            proc.stdout,
            '{"member":"alice","permission":"documents:read",'
            '"roles":["reader"],"allowed":false,'
            '"reason":"权限未授予","granted_roles":[]}\n',
        )
        # editor 的授权仍在库中。
        self.assertEqual(self.stored_rules(), [("editor", PERMISSION_READ)])

    def test_unconfigured_members_have_empty_role_arrays(self):
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
                    f"未配置成员 {member!r} 的两个角色数组都应为空，"
                    f"实际为 {result!r}",
                )

    def test_ungranted_permission_has_empty_granted_roles(self):
        # reader 只获授 read：查询 write 时来源为空，但 roles 保留固定角色。
        self.grant("reader", PERMISSION_READ).check_returncode()
        argv = ("check", "alice", PERMISSION_WRITE, "--explain")
        result = self.assert_success(self.run_rbac(*argv), argv)
        self.assertEqual(
            result,
            {
                "member": "alice",
                "permission": PERMISSION_WRITE,
                "roles": ["reader"],
                "allowed": False,
                "reason": "权限未授予",
                "granted_roles": [],
            },
        )

    def test_empty_rulebase_explain_shape(self):
        # 查询本身建库：alice 仍有 reader 角色，granted_roles 为空。
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
        self.assertTrue(os.path.exists(self.db_path))

    def test_names_trimmed_and_matched_case_sensitively(self):
        self.grant("reader", PERMISSION_READ).check_returncode()

        # 带首尾空白的名称规整后命中同一授权。
        argv = ("check", "\t alice \n", f"  {PERMISSION_READ}  ", "--explain")
        result = self.assert_success(self.run_rbac(*argv), argv)
        self.assertEqual(result["member"], "alice")
        self.assertEqual(result["permission"], PERMISSION_READ)
        self.assertEqual(result["allowed"], True)
        self.assertEqual(result["granted_roles"], ["reader"])

        # 大小写不同的权限不命中：来源为空；通配符形态不作特殊解释。
        for permission in ("documents:Read", "documents:*", "documents:%"):
            with self.subTest(permission=permission):
                argv = ("check", "alice", permission, "--explain")
                result = self.assert_success(self.run_rbac(*argv), argv)
                self.assertEqual(result["allowed"], False)
                self.assertEqual(result["reason"], "权限未授予")
                self.assertEqual(result["granted_roles"], [])

    def test_explain_is_read_only(self):
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("editor", PERMISSION_WRITE).check_returncode()
        rules_before = self.stored_rules()

        for member, permission in (
            ("alice", PERMISSION_READ),
            ("alice", PERMISSION_WRITE),
            ("bob", PERMISSION_READ),
            ("  alice\t", PERMISSION_READ),
        ):
            with self.subTest(member=member, permission=permission):
                self.assert_success(
                    self.check_explain(member, permission),
                    ("check", member, permission, "--explain"),
                )

        self.assertEqual(
            self.stored_rules(),
            rules_before,
            "--explain 查询应为只读",
        )

    # ---- 名称与存储边界 --------------------------------------------------

    def test_blank_names_are_invalid_and_create_no_database(self):
        cases = [
            ("", PERMISSION_READ),
            ("alice", ""),
            ("   ", PERMISSION_READ),
            ("alice", "\t \n"),
            ("", ""),
        ]
        for index, (member, permission) in enumerate(cases):
            with self.subTest(member=member, permission=permission):
                fresh_db = os.path.join(self.tmpdir, f"explain_invalid_{index}.db")
                argv = ("check", member, permission, "--explain")
                self.assert_invalid_name(
                    self.run_rbac(*argv, db=fresh_db), argv, fresh_db_path=fresh_db
                )

    def test_missing_parent_directory_is_storage_error(self):
        missing_parent_db = os.path.join(self.tmpdir, "missing_dir", "rules.db")
        argv = ("check", "alice", PERMISSION_READ, "--explain")
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

    def test_missing_permission_column_alice_error_bob_normal_denial(self):
        # 已有表缺 permission 列：alice 必须查规则表 -> 存储错误；
        # bob 角色为空 -> 不触碰规则表，仍按成员未配置正常拒绝；不修补结构。
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
        self.assertEqual(
            proc.stdout,
            '{"member":"bob","permission":"documents:read",'
            '"roles":[],"allowed":false,'
            '"reason":"成员未配置","granted_roles":[]}\n',
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


class GrantedRolesForPermissionStoreTests(unittest.TestCase):
    """store 层多角色来源查询的直接单元核对（公开固定配置无法构造该输入）。"""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.conn = store.connect(
            os.path.join(self._tmpdir.name, "rules.db")
        )
        self.addCleanup(self.conn.close)

    def test_overlapping_grants_merge_dedup_and_sort_roles(self):
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

        # 入参角色含重复项：结果仍去重并按码点升序；只针对请求权限。
        self.assertEqual(
            store.list_granted_roles_for_permission(
                self.conn, ["reader", "editor", "reader", "auditor"],
                PERMISSION_READ,
            ),
            ["auditor", "editor", "reader"],
        )
        self.assertEqual(
            store.list_granted_roles_for_permission(
                self.conn, ["reader", "editor", "auditor"], PERMISSION_WRITE
            ),
            ["editor"],
        )

    def test_empty_roles_short_circuits_without_querying(self):
        # 空角色直接返回空列表：缺列的表也不会触发查询错误。
        self.conn.execute("DROP TABLE role_permissions")
        self.conn.execute("CREATE TABLE role_permissions (role TEXT)")
        self.conn.commit()
        self.assertEqual(
            store.list_granted_roles_for_permission(
                self.conn, [], PERMISSION_READ
            ),
            [],
        )

    def test_roles_without_grants_yield_empty_list(self):
        self.conn.execute(
            "INSERT INTO role_permissions (role, permission) VALUES (?, ?)",
            ("viewer", PERMISSION_READ),
        )
        self.conn.commit()
        self.assertEqual(
            store.list_granted_roles_for_permission(
                self.conn, ["reader"], PERMISSION_READ
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
