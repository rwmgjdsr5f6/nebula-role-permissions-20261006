"""export-rules 导出全部直接角色授权规则的回归测试。

只依赖 Python 3 标准库；每个用例使用独立临时数据库目录，结束后自动清理。
从项目根目录执行：

    python -m unittest discover -s tests

覆盖范围：
- 验收样例：reader 的 documents:read、documents:write 与 editor 的
  documents:read 依次导出为 editor/read、reader/read、reader/write；
- 可选 --role ROLE 筛选：只导出指定角色当前保存的授权（含无固定成员的
  角色），权限按码点升序；未出现、已撤销、空库或缺库均返回 {"rules":[]}；
  先去首尾空白再大小写敏感精确匹配，保留内部空白，*、%、_ 为普通字符；
  空字符串或纯空白名称先于任何数据库操作返回 invalid_name（退出码 2）；
  父目录不存在、非 SQLite 文件、表缺少 permission 列统一 storage_error；
- 重复授予已有配对后导出仍只有三条；规则不变时重复导出内容一致；
- 空库与缺失文件（父目录存在）均返回 {"rules":[]}，缺失文件沿用建库行为；
- 未分配给成员的角色同样导出；名称保留大小写、不裁剪，通配符原样输出；
- 角色按完整名称 Unicode 码点升序，角色相同时权限同样排序，组合去重；
- 导出为只读操作，前后授权记录与其他表数据不变；不带 --role 时全量导出
  的内容、排序、格式与退出码保持不变；
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
INVALID_NAME_ERROR = '{"error":"invalid_name"}\n'


class ExportRulesTests(unittest.TestCase):
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

    def export_rules(self, role=None, **kwargs):
        """导出规则；role 非 None 时以 --role 精确筛选指定角色。"""
        argv = ("export-rules",)
        if role is not None:
            argv = ("export-rules", "--role", role)
        return self.run_rbac(*argv, **kwargs)

    def assert_invalid_name(self, proc, argv):
        """名称无效：退出码 2，stdout 为空，stderr 仅为固定错误行。"""
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
            f"输入 {argv!r}：标准错误应为 {INVALID_NAME_ERROR!r}，实际为 {proc.stderr!r}",
        )

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

    def test_export_matches_acceptance_sample(self):
        self.grant_acceptance_sample()

        result = self.assert_success_json(self.export_rules(), "导出验收样例规则库")
        self.assertEqual(
            result,
            {
                "rules": [
                    {"role": "editor", "permission": PERMISSION_READ},
                    {"role": "reader", "permission": PERMISSION_READ},
                    {"role": "reader", "permission": PERMISSION_WRITE},
                ]
            },
            f"导出结果与验收样例不符，实际为 {result!r}",
        )
        self.assertEqual(
            set(result.keys()),
            {"rules"},
            f"顶层应仅有 rules 键，实际为 {set(result.keys())}",
        )
        for entry in result["rules"]:
            self.assertEqual(
                set(entry.keys()),
                {"role", "permission"},
                f"每条规则应仅有 role 和 permission，实际为 {set(entry.keys())}",
            )

    def test_export_after_duplicate_grant_still_unique_and_stable(self):
        self.grant_acceptance_sample()
        # 重复授予已有配对：导出仍只有三条，且重复导出内容一致。
        self.assert_success_json(
            self.grant("reader", PERMISSION_READ), "重复授予 reader/documents:read"
        )
        self.assert_success_json(
            self.grant("editor", PERMISSION_READ), "重复授予 editor/documents:read"
        )

        first = self.assert_success_json(self.export_rules(), "重复授予后首次导出")
        second = self.assert_success_json(self.export_rules(), "重复授予后再次导出")
        expected = [
            {"role": "editor", "permission": PERMISSION_READ},
            {"role": "reader", "permission": PERMISSION_READ},
            {"role": "reader", "permission": PERMISSION_WRITE},
        ]
        self.assertEqual(
            first["rules"],
            expected,
            f"重复授予后导出应仍只有三条配对，实际为 {first['rules']!r}",
        )
        self.assertEqual(
            first,
            second,
            f"规则不变时重复导出应一致，首次 {first!r}，再次 {second!r}",
        )

    def test_export_on_empty_database_returns_empty_rules(self):
        # 先通过 grant 再 revoke 造出已有空库。
        self.assert_success_json(
            self.grant("reader", PERMISSION_READ), "预置授权后撤销以造空库"
        )
        self.assert_success_json(
            self.run_rbac("revoke", "reader", PERMISSION_READ), "撤销唯一授权"
        )
        self.assertEqual(self.stored_rules(), [], "测试前置：授权记录应为空")

        result = self.assert_success_json(self.export_rules(), "导出已有空库")
        self.assertEqual(
            result,
            {"rules": []},
            f"已有空库应返回空 rules 数组，实际为 {result!r}",
        )

    def test_export_on_missing_db_initializes_and_returns_empty(self):
        # 数据库文件尚不存在但父目录存在：沿用建库行为。
        self.assertFalse(os.path.exists(self.db_path), "测试前置：数据库应尚未创建")
        result = self.assert_success_json(self.export_rules(), "导出新规则库")
        self.assertEqual(
            result,
            {"rules": []},
            f"新规则库应返回空 rules 数组，实际为 {result!r}",
        )
        self.assertTrue(
            os.path.exists(self.db_path),
            "父目录存在时导出应沿用建库行为创建数据库文件",
        )

    # ---- 内容细节 -------------------------------------------------------

    def test_export_includes_roles_without_members(self):
        # 未关联任何成员的角色同样导出。
        self.assert_success_json(
            self.grant("ghost", "ghost:only"), "授予未关联成员的角色 ghost"
        )
        self.assert_success_json(
            self.grant("reader", PERMISSION_READ), "授予 reader/documents:read"
        )

        result = self.assert_success_json(self.export_rules(), "导出含无成员角色")
        self.assertEqual(
            result["rules"],
            [
                {"role": "ghost", "permission": "ghost:only"},
                {"role": "reader", "permission": PERMISSION_READ},
            ],
            f"无成员角色应包含在导出中，实际为 {result['rules']!r}",
        )

    def test_export_sorts_by_codepoint_and_preserves_names(self):
        # 名称保留大小写、不裁剪通配符；角色与权限均按码点升序。
        grants = [
            ("b", "中"),
            ("A", "b"),
            ("A", "a"),
            ("reader", "documents:*"),
            ("reader", "documents:%"),
            ("reader", "documents:_"),
            ("Reader", PERMISSION_READ),
        ]
        for role, permission in grants:
            self.assert_success_json(self.grant(role, permission), f"预置 {role}/{permission}")

        result = self.assert_success_json(self.export_rules(), "导出码点排序样例")
        self.assertEqual(
            result["rules"],
            [
                {"role": "A", "permission": "a"},
                {"role": "A", "permission": "b"},
                {"role": "Reader", "permission": PERMISSION_READ},
                {"role": "b", "permission": "中"},
                {"role": "reader", "permission": "documents:%"},
                {"role": "reader", "permission": "documents:*"},
                {"role": "reader", "permission": "documents:_"},
            ],
            f"码点排序或名称保留不符合预期，实际为 {result['rules']!r}",
        )

    def test_export_is_read_only(self):
        self.grant_acceptance_sample()
        rules_before = self.stored_rules()
        # 另建一张已有表，确认导出不影响其他表数据。
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("CREATE TABLE notes (body TEXT)")
            conn.execute("INSERT INTO notes VALUES ('keep me')")

        self.assert_success_json(self.export_rules(), "第一次导出")
        self.assert_success_json(self.export_rules(), "第二次导出")

        self.assertEqual(
            rules_before,
            self.stored_rules(),
            f"导出不应改动授权记录，之前 {rules_before!r}，之后 {self.stored_rules()!r}",
        )
        with sqlite3.connect(self.db_path) as conn:
            notes = conn.execute("SELECT body FROM notes").fetchall()
        self.assertEqual(
            notes,
            [("keep me",)],
            f"导出不应改动其他表数据，实际为 {notes!r}",
        )

    # ---- --role 筛选 ----------------------------------------------------

    def test_export_role_matches_acceptance_sample(self):
        self.grant_acceptance_sample()

        result = self.assert_success_json(
            self.export_rules(role="reader"), "--role reader 导出验收样例"
        )
        self.assertEqual(
            result,
            {
                "rules": [
                    {"role": "reader", "permission": PERMISSION_READ},
                    {"role": "reader", "permission": PERMISSION_WRITE},
                ]
            },
            f"--role reader 应只含 reader 的两条授权，实际为 {result!r}",
        )
        self.assertEqual(set(result.keys()), {"rules"})
        for entry in result["rules"]:
            self.assertEqual(set(entry.keys()), {"role", "permission"})

        # editor 的授权仍在库中，按 editor 筛选可单独取得。
        editor_result = self.assert_success_json(
            self.export_rules(role="editor"), "--role editor 导出验收样例"
        )
        self.assertEqual(
            editor_result,
            {"rules": [{"role": "editor", "permission": PERMISSION_READ}]},
            f"--role editor 应只含 editor 的一条授权，实际为 {editor_result!r}",
        )

    def test_export_role_includes_roles_without_members(self):
        # 角色即使没有绑定任何固定成员，只要存在授权就正常导出。
        self.assert_success_json(
            self.grant("ghost", "ghost:only"), "授予未关联成员的角色 ghost"
        )
        self.assert_success_json(
            self.grant("reader", PERMISSION_READ), "授予 reader/documents:read"
        )

        result = self.assert_success_json(
            self.export_rules(role="ghost"), "--role ghost 导出无成员角色"
        )
        self.assertEqual(
            result,
            {"rules": [{"role": "ghost", "permission": "ghost:only"}]},
            f"无成员角色的授权应能按角色导出，实际为 {result!r}",
        )

    def test_export_role_unknown_revoked_and_empty_database(self):
        # 角色从未出现：成功空结果。
        result = self.assert_success_json(
            self.export_rules(role="ghost"), "空库导出未出现角色"
        )
        self.assertEqual(result, {"rules": []})

        # 授权已全部撤销：成功空结果。
        self.grant_acceptance_sample()
        for role, permission in (
            ("reader", PERMISSION_READ),
            ("reader", PERMISSION_WRITE),
        ):
            self.assert_success_json(
                self.run_rbac("revoke", role, permission),
                f"撤销 {role}/{permission}",
            )
        result = self.assert_success_json(
            self.export_rules(role="reader"), "授权全部撤销后按角色导出"
        )
        self.assertEqual(
            result,
            {"rules": []},
            f"授权全部撤销后应返回空 rules，实际为 {result!r}",
        )

        # 缺库（父目录存在）时同样成功空结果，并沿用建库行为。
        new_db = os.path.join(self.tmpdir, "fresh.db")
        self.assertFalse(os.path.exists(new_db), "测试前置：fresh.db 应不存在")
        result = self.assert_success_json(
            self.export_rules(role="reader", db=new_db), "缺库按角色导出"
        )
        self.assertEqual(result, {"rules": []})
        self.assertTrue(
            os.path.exists(new_db),
            "父目录存在时缺库导出应沿用建库行为创建数据库文件",
        )

    def test_export_role_trims_whitespace_matches_exactly_and_case_sensitively(self):
        grants = [
            ("reader", PERMISSION_READ),
            ("reader", PERMISSION_WRITE),
            ("Reader", PERMISSION_READ),
            ("read er", "documents:internal"),
            ("reader*", "documents:star"),
            ("reader%", "documents:percent"),
            ("reader_", "documents:underscore"),
        ]
        for role, permission in grants:
            self.assert_success_json(self.grant(role, permission), f"预置 {role}/{permission}")

        # 首尾空白在规整时去除，内部空白原样保留。
        result = self.assert_success_json(
            self.export_rules(role="  reader\t"), "--role '  reader\\t'"
        )
        self.assertEqual(
            result,
            {
                "rules": [
                    {"role": "reader", "permission": PERMISSION_READ},
                    {"role": "reader", "permission": PERMISSION_WRITE},
                ]
            },
            f"首尾空白应被去除后精确匹配 reader，实际为 {result!r}",
        )
        result = self.assert_success_json(
            self.export_rules(role=" read er "), "--role ' read er ' 保留内部空白"
        )
        self.assertEqual(
            result,
            {"rules": [{"role": "read er", "permission": "documents:internal"}]},
            f"内部空白必须保留并精确匹配，实际为 {result!r}",
        )

        # 大小写敏感：Reader 与 reader 是两个角色，互不混入。
        result = self.assert_success_json(
            self.export_rules(role="Reader"), "--role Reader 大小写敏感"
        )
        self.assertEqual(
            result,
            {"rules": [{"role": "Reader", "permission": PERMISSION_READ}]},
            f"大小写敏感匹配失败，实际为 {result!r}",
        )

        # *、%、_ 都是普通字符，不作通配符解释。
        for role, permission in (
            ("reader*", "documents:star"),
            ("reader%", "documents:percent"),
            ("reader_", "documents:underscore"),
        ):
            result = self.assert_success_json(
                self.export_rules(role=role), f"--role {role!r} 普通字符匹配"
            )
            self.assertEqual(
                result,
                {"rules": [{"role": role, "permission": permission}]},
                f"{role!r} 应按普通名称精确匹配一条授权，实际为 {result!r}",
            )
        # 通配符不得匹配出 reader 的其他授权。
        result = self.assert_success_json(
            self.export_rules(role="reader%"), "--role reader% 不做通配"
        )
        self.assertEqual(
            result,
            {"rules": [{"role": "reader%", "permission": "documents:percent"}]},
            f"% 不应匹配其他 reader* 角色，实际为 {result!r}",
        )

    def test_export_role_permissions_sorted_by_codepoint(self):
        for permission in ("中", "a", "b", "documents:%", "documents:*", "documents:_"):
            self.assert_success_json(
                self.grant("reader", permission), f"预置 reader/{permission}"
            )
        # 其他角色的授权不参与结果，也不影响排序。
        self.assert_success_json(self.grant("editor", "zzz"), "预置 editor/zzz")

        result = self.assert_success_json(
            self.export_rules(role="reader"), "--role reader 权限码点排序"
        )
        self.assertEqual(
            [entry["permission"] for entry in result["rules"]],
            ["a", "b", "documents:%", "documents:*", "documents:_", "中"],
            f"权限应按完整名称 Unicode 码点升序，实际为 {result['rules']!r}",
        )
        self.assertTrue(
            all(entry["role"] == "reader" for entry in result["rules"]),
            f"结果中每项角色都应为 reader，实际为 {result['rules']!r}",
        )

    def test_export_role_is_read_only_stable_and_same_shape_without_filter(self):
        self.grant_acceptance_sample()
        rules_before = self.stored_rules()

        first = self.assert_success_json(
            self.export_rules(role="reader"), "按角色首次导出"
        )
        second = self.assert_success_json(
            self.export_rules(role="reader"), "按角色再次导出"
        )
        self.assertEqual(first, second, "规则不变时按角色重复导出应一致")
        self.assertEqual(
            rules_before,
            self.stored_rules(),
            f"按角色导出不应改动授权记录，实际为 {self.stored_rules()!r}",
        )

        # 不带 --role 的全量导出在内容、排序与结构上保持不变。
        full = self.assert_success_json(self.export_rules(), "不带 --role 全量导出")
        self.assertEqual(
            full,
            {
                "rules": [
                    {"role": "editor", "permission": PERMISSION_READ},
                    {"role": "reader", "permission": PERMISSION_READ},
                    {"role": "reader", "permission": PERMISSION_WRITE},
                ]
            },
            f"不带 --role 时全量导出应保持原样，实际为 {full!r}",
        )

    # ---- --role 名称校验先于存储 ----------------------------------------

    def test_export_role_blank_name_is_invalid_name_without_storage_access(self):
        self.grant_acceptance_sample()

        for blank in ("", "   ", "\t \n"):
            argv = ("export-rules", "--role", blank)
            proc = self.run_rbac(*argv)
            self.assert_invalid_name(proc, argv)
            # 授权与数据库未被改动。
            self.assertEqual(
                self.stored_rules(),
                [
                    ("editor", PERMISSION_READ),
                    ("reader", PERMISSION_READ),
                    ("reader", PERMISSION_WRITE),
                ],
                f"输入 {argv!r} 不应改动已有授权",
            )

        # 校验先于任何数据库操作：即使数据库路径同时无效，结果仍是
        # invalid_name（退出码 2），且不创建任何文件。
        invalid_dir_db = os.path.join(self.tmpdir, "no_such_dir", "rules.db")
        for blank in ("", "  "):
            argv = ("export-rules", "--role", blank)
            proc = self.run_rbac(*argv, db=invalid_dir_db)
            self.assert_invalid_name(proc, argv)
            self.assertFalse(
                os.path.exists(invalid_dir_db),
                f"输入 {argv!r}：名称校验失败时不应创建数据库文件",
            )
            self.assertFalse(
                os.path.exists(os.path.dirname(invalid_dir_db)),
                "名称校验失败时不应创建父目录",
            )

    # ---- --role 存储失败 ------------------------------------------------

    def test_export_role_missing_parent_directory_is_storage_error(self):
        missing_parent_db = os.path.join(self.tmpdir, "missing_dir", "rules.db")
        argv = ("export-rules", "--role", "reader")
        proc = self.run_rbac(*argv, db=missing_parent_db)
        self.assert_storage_error(proc, argv)
        self.assertFalse(
            os.path.exists(missing_parent_db),
            "父目录不存在时不应创建数据库文件",
        )

    def test_export_role_non_sqlite_file_is_storage_error_and_untouched(self):
        bad_db = os.path.join(self.tmpdir, "not_sqlite.db")
        original = b"this is not a sqlite database"
        with open(bad_db, "wb") as handle:
            handle.write(original)

        argv = ("export-rules", "--role", "reader")
        proc = self.run_rbac(*argv, db=bad_db)
        self.assert_storage_error(proc, argv)
        with open(bad_db, "rb") as handle:
            self.assertEqual(
                handle.read(),
                original,
                "非 SQLite 文件不应被修复或覆盖",
            )

    def test_export_role_table_missing_permission_column_is_storage_error(self):
        # 已有数据库中 role_permissions 表缺少 permission 列。
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("CREATE TABLE role_permissions (role TEXT NOT NULL)")
            conn.execute("INSERT INTO role_permissions VALUES ('reader')")
        with sqlite3.connect(self.db_path) as conn:
            rows_before = conn.execute(
                "SELECT role FROM role_permissions"
            ).fetchall()

        argv = ("export-rules", "--role", "reader")
        proc = self.run_rbac(*argv, db=self.db_path)
        self.assert_storage_error(proc, argv)

        with sqlite3.connect(self.db_path) as conn:
            rows_after = conn.execute(
                "SELECT role FROM role_permissions"
            ).fetchall()
        self.assertEqual(
            rows_before,
            rows_after,
            f"导出失败不应改动已有数据，之前 {rows_before!r}，之后 {rows_after!r}",
        )

    # ---- 存储失败 -------------------------------------------------------

    def test_export_missing_parent_directory_is_storage_error(self):
        missing_parent_db = os.path.join(self.tmpdir, "missing_dir", "rules.db")
        argv = ("export-rules",)
        proc = self.run_rbac(*argv, db=missing_parent_db)
        self.assert_storage_error(proc, argv)
        self.assertFalse(
            os.path.exists(missing_parent_db),
            "父目录不存在时不应创建数据库文件",
        )

    def test_export_non_sqlite_file_is_storage_error_and_untouched(self):
        bad_db = os.path.join(self.tmpdir, "not_sqlite.db")
        original = b"this is not a sqlite database"
        with open(bad_db, "wb") as handle:
            handle.write(original)

        argv = ("export-rules",)
        proc = self.run_rbac(*argv, db=bad_db)
        self.assert_storage_error(proc, argv)
        with open(bad_db, "rb") as handle:
            self.assertEqual(
                handle.read(),
                original,
                "非 SQLite 文件不应被修复或覆盖",
            )

    def test_export_table_missing_permission_column_is_storage_error(self):
        # 已有数据库中 role_permissions 表缺少 permission 列。
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("CREATE TABLE role_permissions (role TEXT NOT NULL)")
            conn.execute("INSERT INTO role_permissions VALUES ('reader')")
        with sqlite3.connect(self.db_path) as conn:
            rows_before = conn.execute(
                "SELECT role FROM role_permissions"
            ).fetchall()

        argv = ("export-rules",)
        proc = self.run_rbac(*argv, db=self.db_path)
        self.assert_storage_error(proc, argv)

        with sqlite3.connect(self.db_path) as conn:
            rows_after = conn.execute(
                "SELECT role FROM role_permissions"
            ).fetchall()
        self.assertEqual(
            rows_before,
            rows_after,
            f"导出失败不应改动已有数据，之前 {rows_before!r}，之后 {rows_after!r}",
        )


if __name__ == "__main__":
    unittest.main()
