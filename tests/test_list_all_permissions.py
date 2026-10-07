"""list-all-permissions 查询当前权限名称清单的回归测试。

只依赖 Python 3 标准库；每个用例使用独立临时数据库目录，结束后自动清理。
从项目根目录执行：

    python -m unittest discover -s tests

覆盖范围：
- 验收样例：reader 与 editor 均获授 documents:read、reader 另获授
  documents:write，清单为 ["documents:read","documents:write"]；
- 撤销 reader 的读取授权后 editor 仍持有，清单不变；最后一条授权撤销后
  该名称不再出现；
- 空库与缺失文件（父目录存在）均返回 {"permissions":[]}，缺失文件沿用建库行为；
- 未分配给成员的角色所持权限同样计入；同名权限只出现一次；
- 名称保留大小写与内部空白、不裁剪通配符，按完整名称 Unicode 码点升序；
- 查询为只读操作，前后授权记录与其他表数据不变；
- 父目录不存在、文件不是 SQLite、role_permissions 表缺少 permission 列
  统一返回 storage_error（退出码 1），stdout 为空，不修复或覆盖原文件。
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


class ListAllPermissionsTests(unittest.TestCase):
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

    def list_all_permissions(self, **kwargs):
        return self.run_rbac("list-all-permissions", **kwargs)

    def assert_success_json(self, proc, context):
        """成功调用：退出码 0、标准错误为空、标准输出为单个 JSON 对象加换行。"""
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
        self.assertTrue(
            proc.stdout.endswith("\n"),
            f"{context}：标准输出应以换行结束，实际为 {proc.stdout!r}",
        )
        self.assertEqual(
            proc.stdout.count("\n"),
            1,
            f"{context}：标准输出应只有一个 JSON 对象加换行，实际为 {proc.stdout!r}",
        )
        obj = json.loads(proc.stdout[:-1])
        self.assertIsInstance(
            obj,
            dict,
            f"{context}：标准输出应为一个 JSON 对象，实际类型为 {type(obj).__name__}",
        )
        return obj

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

    def grant_acceptance_sample(self):
        """预置验收样例授权：reader 读/写与 editor 读。"""
        for role, permission in (
            ("reader", PERMISSION_READ),
            ("editor", PERMISSION_READ),
            ("reader", PERMISSION_WRITE),
        ):
            proc = self.grant(role, permission)
            self.assertEqual(
                proc.returncode,
                0,
                f"预置授权 {role}/{permission} 失败：{proc.stderr!r}",
            )

    # ---- 主流程 ---------------------------------------------------------

    def test_list_matches_acceptance_sample(self):
        self.grant_acceptance_sample()

        result = self.assert_success_json(
            self.list_all_permissions(), "查询验收样例规则库"
        )
        self.assertEqual(
            result,
            {"permissions": [PERMISSION_READ, PERMISSION_WRITE]},
            f"清单与验收样例不符，实际为 {result!r}",
        )
        self.assertEqual(
            set(result.keys()),
            {"permissions"},
            f"顶层应仅有 permissions 键，实际为 {set(result.keys())}",
        )

    def test_revoke_keeps_permission_while_other_role_holds_it(self):
        self.grant_acceptance_sample()
        # 撤销 reader 的读取授权：editor 仍持有，两项权限均保留。
        self.assert_success_json(
            self.revoke("reader", PERMISSION_READ), "撤销 reader/documents:read"
        )

        result = self.assert_success_json(
            self.list_all_permissions(), "撤销 reader 读取授权后查询"
        )
        self.assertEqual(
            result,
            {"permissions": [PERMISSION_READ, PERMISSION_WRITE]},
            f"editor 仍持有 documents:read，清单应不变，实际为 {result!r}",
        )

    def test_permission_disappears_after_last_grant_revoked(self):
        self.grant_acceptance_sample()
        # 撤销全部 documents:read 授权后，该名称不再出现。
        self.assert_success_json(
            self.revoke("reader", PERMISSION_READ), "撤销 reader/documents:read"
        )
        self.assert_success_json(
            self.revoke("editor", PERMISSION_READ), "撤销 editor/documents:read"
        )

        result = self.assert_success_json(
            self.list_all_permissions(), "撤销全部读取授权后查询"
        )
        self.assertEqual(
            result,
            {"permissions": [PERMISSION_WRITE]},
            f"documents:read 已无人持有，应不再出现，实际为 {result!r}",
        )

    def test_list_on_empty_database_returns_empty_permissions(self):
        # 先通过 grant 再 revoke 造出已有空库。
        self.assert_success_json(
            self.grant("reader", PERMISSION_READ), "预置授权后撤销以造空库"
        )
        self.assert_success_json(
            self.revoke("reader", PERMISSION_READ), "撤销唯一授权"
        )
        self.assertEqual(self.stored_rules(), [], "测试前置：授权记录应为空")

        result = self.assert_success_json(self.list_all_permissions(), "查询已有空库")
        self.assertEqual(
            result,
            {"permissions": []},
            f"已有空库应返回空 permissions 数组，实际为 {result!r}",
        )

    def test_list_on_missing_db_initializes_and_returns_empty(self):
        # 数据库文件尚不存在但父目录存在：沿用建库行为。
        self.assertFalse(os.path.exists(self.db_path), "测试前置：数据库应尚未创建")
        result = self.assert_success_json(self.list_all_permissions(), "查询新规则库")
        self.assertEqual(
            result,
            {"permissions": []},
            f"新规则库应返回空 permissions 数组，实际为 {result!r}",
        )
        self.assertTrue(
            os.path.exists(self.db_path),
            "父目录存在时查询应沿用建库行为创建数据库文件",
        )

    # ---- 内容细节 -------------------------------------------------------

    def test_list_includes_permissions_of_roles_without_members(self):
        # 未关联任何成员的角色所持权限同样计入清单。
        self.assert_success_json(
            self.grant("ghost", "ghost:only"), "授予未关联成员的角色 ghost"
        )
        self.assert_success_json(
            self.grant("reader", PERMISSION_READ), "授予 reader/documents:read"
        )

        result = self.assert_success_json(
            self.list_all_permissions(), "查询含无成员角色的规则库"
        )
        self.assertEqual(
            result["permissions"],
            [PERMISSION_READ, "ghost:only"],
            f"无成员角色所持权限应计入清单，实际为 {result['permissions']!r}",
        )

    def test_list_deduplicates_sorts_by_codepoint_and_preserves_names(self):
        # 同名权限只出现一次；名称保留大小写与内部空白、不裁剪通配符；
        # 按完整名称 Unicode 码点升序。
        grants = [
            ("reader", "b"),
            ("editor", "a"),
            ("reader", "a"),
            ("editor", "中"),
            ("reader", "documents:*"),
            ("editor", "documents:%"),
            ("reader", "documents:_"),
            ("editor", "Documents:Read"),
            ("reader", "with  space"),
        ]
        for role, permission in grants:
            self.assert_success_json(
                self.grant(role, permission), f"预置 {role}/{permission}"
            )

        result = self.assert_success_json(
            self.list_all_permissions(), "查询码点排序样例"
        )
        self.assertEqual(
            result["permissions"],
            [
                "Documents:Read",
                "a",
                "b",
                "documents:%",
                "documents:*",
                "documents:_",
                "with  space",
                "中",
            ],
            f"去重、码点排序或名称保留不符合预期，实际为 {result['permissions']!r}",
        )

    def test_list_is_read_only(self):
        self.grant_acceptance_sample()
        rules_before = self.stored_rules()
        # 另建一张已有表，确认查询不影响其他表数据。
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("CREATE TABLE notes (body TEXT)")
            conn.execute("INSERT INTO notes VALUES ('keep me')")

        self.assert_success_json(self.list_all_permissions(), "第一次查询")
        self.assert_success_json(self.list_all_permissions(), "第二次查询")

        self.assertEqual(
            rules_before,
            self.stored_rules(),
            f"查询不应改动授权记录，之前 {rules_before!r}，之后 {self.stored_rules()!r}",
        )
        with sqlite3.connect(self.db_path) as conn:
            notes = conn.execute("SELECT body FROM notes").fetchall()
        self.assertEqual(
            notes,
            [("keep me",)],
            f"查询不应改动其他表数据，实际为 {notes!r}",
        )

    # ---- 存储失败 -------------------------------------------------------

    def test_list_missing_parent_directory_is_storage_error(self):
        missing_parent_db = os.path.join(self.tmpdir, "missing_dir", "rules.db")
        argv = ("list-all-permissions",)
        proc = self.run_rbac(*argv, db=missing_parent_db)
        self.assert_storage_error(proc, argv)
        self.assertFalse(
            os.path.exists(missing_parent_db),
            "父目录不存在时不应创建数据库文件",
        )

    def test_list_non_sqlite_file_is_storage_error_and_untouched(self):
        bad_db = os.path.join(self.tmpdir, "not_sqlite.db")
        original = b"this is not a sqlite database"
        with open(bad_db, "wb") as handle:
            handle.write(original)

        argv = ("list-all-permissions",)
        proc = self.run_rbac(*argv, db=bad_db)
        self.assert_storage_error(proc, argv)
        with open(bad_db, "rb") as handle:
            self.assertEqual(
                handle.read(),
                original,
                "非 SQLite 文件不应被修复或覆盖",
            )

    def test_list_table_missing_permission_column_is_storage_error(self):
        # 已有数据库中 role_permissions 表缺少 permission 列。
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("CREATE TABLE role_permissions (role TEXT NOT NULL)")
            conn.execute("INSERT INTO role_permissions VALUES ('reader')")
        with sqlite3.connect(self.db_path) as conn:
            rows_before = conn.execute(
                "SELECT role FROM role_permissions"
            ).fetchall()

        argv = ("list-all-permissions",)
        proc = self.run_rbac(*argv, db=self.db_path)
        self.assert_storage_error(proc, argv)

        with sqlite3.connect(self.db_path) as conn:
            rows_after = conn.execute(
                "SELECT role FROM role_permissions"
            ).fetchall()
        self.assertEqual(
            rows_before,
            rows_after,
            f"查询失败不应改动已有数据，之前 {rows_before!r}，之后 {rows_after!r}",
        )


if __name__ == "__main__":
    unittest.main()
