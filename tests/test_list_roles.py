"""list-roles 列出当前获授角色入口的回归测试。

只依赖 Python 3 标准库；每个用例使用独立临时数据库目录，结束后自动清理。
从项目根目录执行：

    python -m unittest discover -s tests

通过 `python -m rbac` 子进程走完整公开命令行入口，覆盖范围：
- 验收样例：reader 获授 documents:read、documents:write，editor 获授
  documents:read 时查询得到 {"roles":["editor","reader"]}；撤销 editor 唯一
  授权后查询得到 {"roles":["reader"]}；
- 角色持有多个权限时只出现一次；撤销部分权限后仍保留，最后一条授权撤销后
  从结果消失；未配置固定成员的角色同样列出；
- 角色名按保存值原样返回，保留大小写、中文及内部空白，按完整名称的
  Unicode 码点升序排列；重复查询内容与顺序一致；
- 空库与缺失文件（父目录存在）均返回 {"roles":[]}，缺失文件沿用建库行为；
- 查询为只读操作，前后授权记录与其他表数据不变；
- 父目录不存在、文件不是 SQLite、role_permissions 表缺少 role 列统一返回
  storage_error（退出码 1），stdout 为空，不修复或覆盖原文件。
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
STORAGE_ERROR = '{"error":"storage_error"}\n'


class ListRolesTests(unittest.TestCase):
    """通过 `python -m rbac` 子进程核对列出获授角色入口的对外行为。"""

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

    def list_roles(self, **kwargs):
        return self.run_rbac("list-roles", **kwargs)

    def assert_roles_equal(self, proc, expected_roles):
        """成功查询：退出码 0、stderr 为空，stdout 恰为紧凑 JSON 加换行。"""
        argv = ("list-roles",)
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
        expected = {"roles": expected_roles}
        # 紧凑 UTF-8 JSON：确保对外字节形态恰为一个对象加换行。
        expected_stdout = (
            json.dumps(expected, ensure_ascii=False, separators=(",", ":")) + "\n"
        )
        self.assertEqual(
            proc.stdout,
            expected_stdout,
            f"输入 {argv!r}：标准输出字节形态与预期不符，"
            f"期望 {expected_stdout!r}，实际为 {proc.stdout!r}",
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
            f"输入 {argv!r}：storage_error 时标准输出应为空（不得以空数组代替），"
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

    def grant_acceptance_sample(self):
        """预置验收样例授权：reader 读/写与 editor 读。"""
        for role, permission in (
            ("reader", PERMISSION_READ),
            ("reader", PERMISSION_WRITE),
            ("editor", PERMISSION_READ),
        ):
            proc = self.grant(role, permission)
            self.assertEqual(
                proc.returncode,
                0,
                f"预置授权 {role}/{permission} 失败：{proc.stderr!r}",
            )

    # ---- 主流程 ---------------------------------------------------------

    def test_acceptance_sample_lists_editor_and_reader(self):
        self.grant_acceptance_sample()

        result = self.assert_roles_equal(self.list_roles(), ["editor", "reader"])
        self.assertEqual(
            set(result.keys()),
            {"roles"},
            f"顶层应仅有 roles 键，实际为 {set(result.keys())}",
        )

        # 撤销 editor 唯一的授权后，editor 从结果消失。
        revoke_proc = self.revoke("editor", PERMISSION_READ)
        self.assertEqual(
            revoke_proc.returncode,
            0,
            f"撤销 editor/documents:read 失败：{revoke_proc.stderr!r}",
        )
        self.assert_roles_equal(self.list_roles(), ["reader"])

    def test_role_with_multiple_permissions_appears_once(self):
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("reader", PERMISSION_WRITE).check_returncode()
        # 重复授予已有配对：结果仍只出现一次。
        self.grant("reader", PERMISSION_READ).check_returncode()

        self.assert_roles_equal(self.list_roles(), ["reader"])

    def test_revoke_keeps_role_until_last_grant_removed(self):
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.grant("reader", PERMISSION_WRITE).check_returncode()

        # 撤销一条权限后角色仍持有其他授权，继续出现。
        self.revoke("reader", PERMISSION_READ).check_returncode()
        self.assert_roles_equal(self.list_roles(), ["reader"])

        # 最后一条授权撤销后角色从结果消失。
        self.revoke("reader", PERMISSION_WRITE).check_returncode()
        self.assert_roles_equal(self.list_roles(), [])

    def test_roles_without_configured_members_are_included(self):
        # 固定成员映射中只有 alice->reader；ghost 没有任何成员绑定，
        # 但只要持有授权就应出现在结果中。
        self.grant("ghost", "ghost:only").check_returncode()
        self.grant("reader", PERMISSION_READ).check_returncode()

        self.assert_roles_equal(self.list_roles(), ["ghost", "reader"])

    def test_names_preserved_and_sorted_by_codepoint(self):
        # 名称保留大小写、中文及内部空白；按完整名称的 Unicode 码点升序。
        for role in ("中 文", "a", "A", "reader", "Reader"):
            self.grant(role, PERMISSION_READ).check_returncode()

        self.assert_roles_equal(
            self.list_roles(), ["A", "Reader", "a", "reader", "中 文"]
        )

    def test_repeated_queries_are_stable(self):
        self.grant_acceptance_sample()

        first = self.list_roles()
        second = self.list_roles()
        self.assert_roles_equal(first, ["editor", "reader"])
        self.assertEqual(
            first.stdout,
            second.stdout,
            f"规则不变时重复查询应一致，首次 {first.stdout!r}，"
            f"再次 {second.stdout!r}",
        )

    # ---- 空库与建库行为 ---------------------------------------------------

    def test_empty_database_returns_empty_roles(self):
        # 先通过 grant 再 revoke 造出已有空库。
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.revoke("reader", PERMISSION_READ).check_returncode()
        self.assertEqual(self.stored_rules(), [], "测试前置：授权记录应为空")

        self.assert_roles_equal(self.list_roles(), [])

    def test_missing_db_with_existing_parent_is_created_and_returns_empty(self):
        self.assertFalse(
            os.path.exists(self.db_path), "测试前置：规则库文件应尚未创建"
        )

        # 父目录已存在而文件不存在：查询应初始化可用空库并返回空角色数组。
        self.assert_roles_equal(self.list_roles(), [])
        self.assertTrue(
            os.path.exists(self.db_path),
            "父目录存在时查询应创建规则库文件",
        )

        # 创建出的库必须可用：授权后再次查询即可看到新角色。
        self.grant("reader", PERMISSION_READ).check_returncode()
        self.assert_roles_equal(self.list_roles(), ["reader"])

    # ---- 只读性 -----------------------------------------------------------

    def test_query_is_read_only(self):
        self.grant_acceptance_sample()
        rules_before = self.stored_rules()
        # 另建一张已有表，确认查询不影响其他表数据。
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("CREATE TABLE notes (body TEXT)")
            conn.execute("INSERT INTO notes VALUES ('keep me')")

        self.assert_roles_equal(self.list_roles(), ["editor", "reader"])
        self.assert_roles_equal(self.list_roles(), ["editor", "reader"])

        self.assertEqual(
            self.stored_rules(),
            rules_before,
            f"查询不应改动授权记录，之前 {rules_before!r}，"
            f"之后 {self.stored_rules()!r}",
        )
        with sqlite3.connect(self.db_path) as conn:
            notes = conn.execute("SELECT body FROM notes").fetchall()
        self.assertEqual(
            notes,
            [("keep me",)],
            f"查询不应改动其他表数据，实际为 {notes!r}",
        )

    # ---- 存储失败 ---------------------------------------------------------

    def test_missing_parent_directory_is_storage_error(self):
        missing_parent_db = os.path.join(self.tmpdir, "missing_dir", "rules.db")
        argv = ("list-roles",)
        proc = self.run_rbac(*argv, db=missing_parent_db)
        self.assert_storage_error(proc, argv)
        self.assertFalse(
            os.path.exists(missing_parent_db),
            "父目录不存在时不应创建数据库文件",
        )

    def test_non_sqlite_file_is_storage_error_and_untouched(self):
        bad_db = os.path.join(self.tmpdir, "not_sqlite.db")
        original = b"this is not a sqlite database"
        with open(bad_db, "wb") as handle:
            handle.write(original)

        argv = ("list-roles",)
        proc = self.run_rbac(*argv, db=bad_db)
        self.assert_storage_error(proc, argv)
        with open(bad_db, "rb") as handle:
            self.assertEqual(
                handle.read(),
                original,
                "非 SQLite 文件不应被修复或覆盖",
            )

    def test_table_missing_role_column_is_storage_error_and_preserves_data(self):
        # 已有数据库中 role_permissions 表缺少 role 列。
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("CREATE TABLE role_permissions (permission TEXT NOT NULL)")
            conn.execute("INSERT INTO role_permissions VALUES ('documents:read')")
        with sqlite3.connect(self.db_path) as conn:
            rows_before = conn.execute(
                "SELECT permission FROM role_permissions"
            ).fetchall()

        argv = ("list-roles",)
        proc = self.run_rbac(*argv, db=self.db_path)
        self.assert_storage_error(proc, argv)

        with sqlite3.connect(self.db_path) as conn:
            rows_after = conn.execute(
                "SELECT permission FROM role_permissions"
            ).fetchall()
        self.assertEqual(
            rows_before,
            rows_after,
            f"查询失败不应改动已有数据，之前 {rows_before!r}，之后 {rows_after!r}",
        )


if __name__ == "__main__":
    unittest.main()
