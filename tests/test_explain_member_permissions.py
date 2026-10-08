"""list-member-permissions --explain 授权来源说明入口的回归测试。

只依赖 Python 3 标准库；每个用例使用独立临时数据库目录，结束后自动清理。
从项目根目录执行：

    python -m unittest discover -s tests

通过 `python -m rbac` 子进程走完整公开命令行入口，覆盖范围：
- 验收样例：仅含 reader 与 editor 各自获授 documents:read 的两条规则时，
  alice --explain 的 permissions 为 ["documents:read"]，sources 恰为
  [{"permission":"documents:read","roles":["reader"]}]，不包含 editor；
- 撤销 reader 的这条授权后，解释查询 permissions 与 sources 均为空，
  roles 仍为 ["reader"]；
- 不带 --explain 时输出仍只含 member、roles、permissions 三个字段，
  字节形态与既有行为完全一致；
- sources 与 permissions 一一对应，每项只含 permission、roles 两个字段，
  来源角色只包含成员固定绑定且确实获授该权限的角色，不出现空来源项；
- 未配置成员 bob 与大小写不同的 Alice：roles、permissions、sources 均为空；
- 查询只读：解释查询不改变任何授权记录；
- 沿用既有边界：空/纯空白成员名退出码 2、stdout 为空、stderr 恰为
  {"error":"invalid_name"} 加换行且不建库；父目录缺失或文件不是 SQLite 时
  退出码 1、stdout 为空、stderr 恰为 {"error":"storage_error"} 加换行；
  已有表缺 permission 列时 alice 存储失败、bob 仍成功空汇总，不修补结构。
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

# 不兼容的表结构：只有 role 列，缺少 permission 列。
_INCOMPATIBLE_SCHEMA = "CREATE TABLE role_permissions (role TEXT)"

# 非数据库文件的固定内容：连续 128 个 ASCII 字符 x，绝不经过 SQLite 初始化。
_NON_SQLITE_BYTES = b"x" * 128


class ExplainMemberPermissionsTests(unittest.TestCase):
    """通过 `python -m rbac` 子进程核对 --explain 开关的对外行为。"""

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

    def stored_rules(self, db_path=None):
        """直接读取 SQLite，返回排序后的 (role, permission) 授权记录。"""
        path = self.db_path if db_path is None else db_path
        with sqlite3.connect(path) as conn:
            return sorted(
                conn.execute(
                    "SELECT role, permission FROM role_permissions"
                ).fetchall()
            )

    def assert_explain_success(self, proc, argv):
        """成功解释查询：退出码 0、stderr 为空，stdout 恰为四字段 JSON 加换行。

        返回解析后的对象，并核对输出含 member、roles、permissions、sources
        四个字段且无其他字段。
        """
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
        self.assertIsInstance(result, dict)
        self.assertEqual(
            set(result.keys()),
            {"member", "roles", "permissions", "sources"},
            f"输入 {argv!r}：--explain 输出应恰含 member、roles、permissions、"
            f"sources 四个字段，实际键为 {set(result.keys())}",
        )
        return result

    def assert_invalid_name(self, proc, argv, fresh_db_path=None):
        """空名称/纯空白：退出码 2，stdout 为空，stderr 仅为固定错误行。"""
        self.assertEqual(proc.returncode, 2, f"输入 {argv!r}：{proc!r}")
        self.assertEqual(proc.stdout, "", f"输入 {argv!r}：{proc!r}")
        self.assertEqual(proc.stderr, INVALID_NAME_ERROR, f"输入 {argv!r}：{proc!r}")
        if fresh_db_path is not None:
            self.assertFalse(
                os.path.exists(fresh_db_path),
                f"输入 {argv!r}：空名称不应创建数据库文件 {fresh_db_path}",
            )

    def assert_storage_error(self, proc, argv):
        """存储失败：退出码 1，stdout 为空，stderr 仅为固定错误行。"""
        self.assertEqual(proc.returncode, 1, f"输入 {argv!r}：{proc!r}")
        self.assertEqual(proc.stdout, "", f"输入 {argv!r}：{proc!r}")
        self.assertEqual(proc.stderr, STORAGE_ERROR, f"输入 {argv!r}：{proc!r}")
        self.assertNotIn("Traceback", proc.stderr, f"输入 {argv!r}：{proc!r}")

    # ---- 验收主路径 -----------------------------------------------------

    def test_acceptance_reader_and_editor_both_granted_excludes_editor(self):
        # 数据库仅含 reader 与 editor 各自获授 documents:read 的两条规则。
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("editor", PERMISSION_READ).check_returncode()

        argv = ("list-member-permissions", "alice", "--explain")
        proc = self.run_rbac(*argv)
        result = self.assert_explain_success(proc, argv)

        self.assertEqual(
            result["roles"],
            ["reader"],
            f"alice 固定角色应为 ['reader']，实际为 {result['roles']!r}",
        )
        self.assertEqual(
            result["permissions"],
            [PERMISSION_READ],
            f"permissions 应为 {[PERMISSION_READ]!r}，"
            f"实际为 {result['permissions']!r}",
        )
        # 来源只含成员固定绑定且确实获授的 reader；editor 虽持有同一权限，
        # 但 alice 未绑定 editor，不得出现。
        self.assertEqual(
            result["sources"],
            [{"permission": PERMISSION_READ, "roles": ["reader"]}],
            f"sources 与预期不符，实际为 {result['sources']!r}",
        )

        # 字节形态钉死：四字段紧凑 UTF-8 JSON 加恰好一个换行。
        expected_stdout = (
            json.dumps(
                {
                    "member": "alice",
                    "roles": ["reader"],
                    "permissions": [PERMISSION_READ],
                    "sources": [
                        {"permission": PERMISSION_READ, "roles": ["reader"]}
                    ],
                },
                ensure_ascii=False,
                separators=(",", ":"),
            )
            + "\n"
        )
        self.assertEqual(
            proc.stdout,
            expected_stdout,
            f"标准输出字节形态与预期不符：期望 {expected_stdout!r}，"
            f"实际为 {proc.stdout!r}",
        )

        # 授权记录仍是两条：排除 editor 是来源隔离而非授权缺失。
        self.assertEqual(
            self.stored_rules(),
            [("editor", PERMISSION_READ), ("reader", PERMISSION_READ)],
        )

    def test_revoke_reader_grant_leaves_empty_permissions_and_sources(self):
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("editor", PERMISSION_READ).check_returncode()

        # 撤销 reader 的这条授权后：permissions、sources 均为空，
        # roles 仍为 ["reader"]；editor 的授权与 alice 无关。
        self.revoke("reader", PERMISSION_READ).check_returncode()

        argv = ("list-member-permissions", "alice", "--explain")
        proc = self.run_rbac(*argv)
        result = self.assert_explain_success(proc, argv)
        self.assertEqual(
            result,
            {
                "member": "alice",
                "roles": ["reader"],
                "permissions": [],
                "sources": [],
            },
            f"撤销后解释结果与预期不符，实际为 {result!r}",
        )
        self.assertEqual(
            self.stored_rules(),
            [("editor", PERMISSION_READ)],
            f"撤销只应删除 reader 的一条，实际为 {self.stored_rules()!r}",
        )

    def test_sources_correspond_one_to_one_with_permissions(self):
        # reader 获授三个权限（含重复授予去重），editor 的权限与 alice 无关。
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("reader", PERMISSION_WRITE).check_returncode()
        self.grant("reader", PERMISSION_EXPORT).check_returncode()
        self.grant("editor", "editor-only").check_returncode()

        proc = self.explain("alice")
        result = self.assert_explain_success(
            proc, ("list-member-permissions", "alice", "--explain")
        )

        expected_permissions = sorted(
            {PERMISSION_READ, PERMISSION_WRITE, PERMISSION_EXPORT}
        )
        self.assertEqual(result["permissions"], expected_permissions)

        # sources 与 permissions 等长、顺序一致、逐项 permission 对齐。
        self.assertEqual(len(result["sources"]), len(result["permissions"]))
        self.assertEqual(
            [item["permission"] for item in result["sources"]],
            result["permissions"],
            f"sources 应与 permissions 一一对应，实际为 {result['sources']!r}",
        )
        for item in result["sources"]:
            # 每项只含 permission、roles 两个字段。
            self.assertEqual(set(item.keys()), {"permission", "roles"})
            # 不出现空来源项。
            self.assertTrue(
                item["roles"],
                f"权限 {item['permission']} 的来源角色不得为空",
            )
            self.assertEqual(
                item["roles"], ["reader"], f"来源应只含 reader，实际为 {item!r}"
            )
            # 角色去重。
            self.assertEqual(len(item["roles"]), len(set(item["roles"])))

    def test_explain_flag_also_accepted_before_member(self):
        # argparse 选项可位于位置参数前后，两种写法结果应一致。
        self.grant("reader", PERMISSION_READ).check_returncode()
        after = self.run_rbac("list-member-permissions", "alice", "--explain")
        before = self.run_rbac("list-member-permissions", "--explain", "alice")
        self.assertEqual(after.returncode, 0, f"{after!r}")
        self.assertEqual(before.returncode, 0, f"{before!r}")
        self.assertEqual(before.stdout, after.stdout)

    def test_unconfigured_members_have_empty_roles_permissions_and_sources(self):
        # 库中即便存在授权，未配置成员的三个数组仍全部为空。
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("editor", PERMISSION_WRITE).check_returncode()

        for member in ("bob", "Alice"):
            with self.subTest(member=member):
                proc = self.explain(member)
                result = self.assert_explain_success(
                    proc, ("list-member-permissions", member, "--explain")
                )
                self.assertEqual(
                    result,
                    {
                        "member": member,
                        "roles": [],
                        "permissions": [],
                        "sources": [],
                    },
                    f"未配置成员 {member!r} 的解释结果与预期不符，"
                    f"实际为 {result!r}",
                )

    def test_explain_query_is_read_only(self):
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("editor", PERMISSION_WRITE).check_returncode()
        rules_before = self.stored_rules()

        for member in ("alice", "bob", "Alice", "  alice\t"):
            with self.subTest(member=member):
                proc = self.explain(member)
                self.assertEqual(proc.returncode, 0, f"{member!r}: {proc!r}")

        self.assertEqual(self.stored_rules(), rules_before)

    # ---- 不带开关时行为不变 ---------------------------------------------

    def test_without_flag_output_has_exactly_three_fields(self):
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("editor", PERMISSION_READ).check_returncode()

        proc = self.run_rbac("list-member-permissions", "alice")
        self.assertEqual(proc.returncode, 0, f"{proc!r}")
        self.assertEqual(proc.stderr, "")
        expected = (
            '{"member":"alice","roles":["reader"],'
            '"permissions":["documents:read"]}\n'
        )
        self.assertEqual(
            proc.stdout,
            expected,
            f"不带开关时应保持三字段既有形态，实际为 {proc.stdout!r}",
        )
        result = json.loads(proc.stdout)
        self.assertEqual(set(result.keys()), {"member", "roles", "permissions"})

    def test_empty_db_alice_without_flag_unchanged(self):
        proc = self.run_rbac("list-member-permissions", "alice")
        self.assertEqual(
            proc.stdout,
            '{"member":"alice","roles":["reader"],"permissions":[]}\n',
        )

    # ---- 名称与存储边界 -------------------------------------------------

    def test_blank_member_with_explain_is_invalid_and_creates_no_database(self):
        for index, member in enumerate(("", "   ", "\t \n")):
            with self.subTest(member=member):
                fresh_db = os.path.join(self.tmpdir, f"invalid_{index}.db")
                argv = ("list-member-permissions", member, "--explain")
                self.assert_invalid_name(
                    self.run_rbac(*argv, db=fresh_db), argv, fresh_db_path=fresh_db
                )

    def test_invalid_name_takes_precedence_over_missing_parent_with_explain(self):
        missing_parent_db = os.path.join(self.tmpdir, "missing_dir", "rules.db")
        argv = ("list-member-permissions", " ", "--explain")
        self.assert_invalid_name(
            self.run_rbac(*argv, db=missing_parent_db),
            argv,
            fresh_db_path=missing_parent_db,
        )
        self.assertFalse(os.path.exists(os.path.dirname(missing_parent_db)))

    def test_missing_parent_directory_with_explain_is_storage_error(self):
        missing_parent_db = os.path.join(self.tmpdir, "missing_dir", "rules.db")
        argv = ("list-member-permissions", "alice", "--explain")
        self.assert_storage_error(
            self.run_rbac(*argv, db=missing_parent_db), argv
        )

    def test_non_sqlite_file_with_explain_is_storage_error_even_for_bob(self):
        with open(self.db_path, "wb") as handle:
            handle.write(_NON_SQLITE_BYTES)
        with open(self.db_path, "rb") as handle:
            bytes_before = handle.read()

        # connect/建表先于成员查询失败：即使 bob 无角色也仍是存储错误。
        argv = ("list-member-permissions", "bob", "--explain")
        self.assert_storage_error(self.run_rbac(*argv), argv)
        with open(self.db_path, "rb") as handle:
            bytes_after = handle.read()
        self.assertEqual(
            bytes_after,
            bytes_before,
            "失败不得改写非 SQLite 文件",
        )

    def test_missing_permission_column_alice_storage_error_bob_empty_success(self):
        # 现存 SQLite 库表只有 role 列并存一行 reader。
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(_INCOMPATIBLE_SCHEMA)
            conn.execute("INSERT INTO role_permissions (role) VALUES ('reader')")

        argv_alice = ("list-member-permissions", "alice", "--explain")
        self.assert_storage_error(self.run_rbac(*argv_alice), argv_alice)

        # bob 角色为空，短路不触碰 permission 列：仍成功且 sources 为空。
        argv_bob = ("list-member-permissions", "bob", "--explain")
        bob_proc = self.run_rbac(*argv_bob)
        self.assertEqual(bob_proc.returncode, 0, f"{bob_proc!r}")
        self.assertEqual(bob_proc.stderr, "")
        self.assertEqual(
            bob_proc.stdout,
            '{"member":"bob","roles":[],"permissions":[],"sources":[]}\n',
            f"bob 解释查询字节形态与预期不符，实际为 {bob_proc.stdout!r}",
        )

        # 不修补结构：列仍只有 role，reader 行保持不变。
        with sqlite3.connect(self.db_path) as conn:
            columns = [
                row[1]
                for row in conn.execute("PRAGMA table_info(role_permissions)").fetchall()
            ]
            rows = conn.execute("SELECT role FROM role_permissions").fetchall()
        self.assertEqual(columns, ["role"])
        self.assertEqual(rows, [("reader",)])

    def test_missing_db_with_explain_creates_empty_database(self):
        # 缺文件但父目录存在且可写：创建空库，alice 空权限空来源。
        argv = ("list-member-permissions", "alice", "--explain")
        proc = self.run_rbac(*argv)
        result = self.assert_explain_success(proc, argv)
        self.assertEqual(
            result,
            {
                "member": "alice",
                "roles": ["reader"],
                "permissions": [],
                "sources": [],
            },
        )
        self.assertTrue(os.path.exists(self.db_path))


if __name__ == "__main__":
    unittest.main()
