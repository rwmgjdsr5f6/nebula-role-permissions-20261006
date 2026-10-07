"""既有表约束阻止新增授权时 grant 行为的回归测试。

测试输入：父目录存在、可正常打开的 SQLite 文件，其中 role_permissions 表
带有额外约束（role 列 UNIQUE，或 permission 列 CHECK），并预置一条
reader / documents:read 规则。此时：

- 组合（角色, 权限）已存在：幂等成功，退出码 0，不增加记录；
- 组合不存在但被既有约束拒绝：退出码 1，标准输出为空，标准错误恰为
  {"error":"storage_error"} 加换行；原有授权、其他表与表结构保持不变；
- 名称为空或纯空白：优先判定 invalid_name，退出码 2，即使存储同时有问题；
- 标准规则库（无额外约束）不受影响：reader 可同时拥有读、写两项权限；
- revoke / check / list-permissions / export-rules 在约束表上保持既有输出，
  固定成员 alice 与 reader 的关系不变。

只依赖 Python 3 标准库与 SQLite；每个用例使用独立临时目录，结束后自动清理。
从项目根目录执行：

    python -m unittest discover -s tests
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

# role 列带唯一约束：reader 已占一行，新权限无法为 reader 新增记录。
_UNIQUE_ROLE_SCHEMA = (
    "CREATE TABLE role_permissions (role TEXT NOT NULL UNIQUE, permission TEXT NOT NULL)"
)
# permission 列带检查约束：documents:write 一律被拒绝写入。
_CHECK_PERMISSION_SCHEMA = (
    "CREATE TABLE role_permissions (role TEXT NOT NULL, "
    "permission TEXT NOT NULL CHECK(permission <> 'documents:write'))"
)


class GrantConstraintRejectionTests(unittest.TestCase):
    """通过 `python -m rbac` 子进程核对约束表上 grant 的对外行为。"""

    def setUp(self):
        # 每个用例独立的临时目录，TemporaryDirectory.cleanup 负责清理。
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.tmpdir = self._tmpdir.name

    # ---- 辅助方法 -------------------------------------------------------

    def make_db(self, name, schema):
        """按给定建表语句建库并预置 reader/documents:read，返回文件路径。"""
        db_path = os.path.join(self.tmpdir, name)
        with sqlite3.connect(db_path) as conn:
            conn.execute(schema)
            conn.execute(
                "INSERT INTO role_permissions (role, permission) VALUES (?, ?)",
                ("reader", PERMISSION_READ),
            )
        return db_path

    def run_rbac(self, *argv, db):
        """运行 rbac 命令行，返回 CompletedProcess（文本模式、UTF-8）。"""
        command = [
            sys.executable,
            "-m",
            "rbac",
            "--db",
            db,
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

    def stored_state(self, db_path):
        """直接读取 SQLite，返回 (建表语句, 排序后的全部行)。"""
        with sqlite3.connect(db_path) as conn:
            schema = conn.execute(
                "SELECT sql FROM sqlite_master WHERE name = 'role_permissions'"
            ).fetchone()[0]
            rows = sorted(
                conn.execute(
                    "SELECT role, permission FROM role_permissions"
                ).fetchall()
            )
        return schema, rows

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
            f"输入 {argv!r}：storage_error 时标准输出应为空（不得夹带成功授权），"
            f"实际为 {proc.stdout!r}",
        )
        self.assertEqual(
            proc.stderr,
            STORAGE_ERROR,
            f"输入 {argv!r}：标准错误应恰为 {STORAGE_ERROR!r}"
            f"（不附加详情或堆栈），实际为 {proc.stderr!r}",
        )

    def assert_success_json(self, proc, context):
        """成功调用：退出码 0、标准错误为空、标准输出为单个 JSON 对象。"""
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
            proc.stdout.endswith("\n") and proc.stdout.count("\n") == 1,
            f"{context}：标准输出应恰为一个 JSON 对象加换行，实际为 {proc.stdout!r}",
        )
        return json.loads(proc.stdout[:-1])

    # ---- role 列 UNIQUE 约束（验收样例） --------------------------------

    def test_unique_role_constraint_rejects_new_permission_and_preserves_data(self):
        db_path = self.make_db("constraint.db", _UNIQUE_ROLE_SCHEMA)
        state_before = self.stored_state(db_path)
        self.assertEqual(
            state_before,
            (_UNIQUE_ROLE_SCHEMA, [("reader", PERMISSION_READ)]),
            f"测试前置：应只有 reader/documents:read 一条记录，实际为 {state_before!r}",
        )

        argv = ("grant", "reader", PERMISSION_WRITE)
        proc = self.run_rbac(*argv, db=db_path)
        self.assert_storage_error(proc, argv)

        # 原有授权与既有表结构保持不变。
        self.assertEqual(
            self.stored_state(db_path),
            state_before,
            f"grant 失败后表结构与数据不应变化，调用前为 {state_before!r}",
        )

        # 原有授权仍可正常查询。
        list_result = self.assert_success_json(
            self.run_rbac("list-permissions", "reader", db=db_path),
            "约束拒绝后列出 reader 的权限",
        )
        self.assertEqual(
            list_result,
            {"role": "reader", "permissions": [PERMISSION_READ]},
            f"list-permissions 结果与预期不符，实际为 {list_result!r}",
        )

    def test_unique_role_constraint_existing_combo_is_idempotent_success(self):
        db_path = self.make_db("constraint.db", _UNIQUE_ROLE_SCHEMA)
        state_before = self.stored_state(db_path)

        # 再次授予已有的 documents:read：幂等成功，不增加记录。
        result = self.assert_success_json(
            self.run_rbac("grant", "reader", PERMISSION_READ, db=db_path),
            "重复授予 reader/documents:read",
        )
        self.assertEqual(
            result,
            {"role": "reader", "permission": PERMISSION_READ},
            f"重复授予的返回内容与预期不符，实际为 {result!r}",
        )
        self.assertEqual(
            self.stored_state(db_path),
            state_before,
            f"幂等授予不应增加记录，调用前为 {state_before!r}，"
            f"实际为 {self.stored_state(db_path)!r}",
        )

    def test_unique_role_constraint_trims_names_before_matching(self):
        db_path = self.make_db("constraint.db", _UNIQUE_ROLE_SCHEMA)
        state_before = self.stored_state(db_path)

        # 名称去除首尾空白后命中既有组合：幂等成功。
        result = self.assert_success_json(
            self.run_rbac(
                "grant", "  reader\t", f"\n{PERMISSION_READ} ", db=db_path
            ),
            "带首尾空白重复授予 reader/documents:read",
        )
        self.assertEqual(
            result,
            {"role": "reader", "permission": PERMISSION_READ},
            f"规整后重复授予的返回内容与预期不符，实际为 {result!r}",
        )

        # 规整后仍是新组合：被唯一约束拒绝。
        argv = ("grant", " reader ", f" {PERMISSION_WRITE}\t")
        proc = self.run_rbac(*argv, db=db_path)
        self.assert_storage_error(proc, argv)

        self.assertEqual(
            self.stored_state(db_path),
            state_before,
            f"约束表上的授予不应改变数据，调用前为 {state_before!r}",
        )

    # ---- permission 列 CHECK 约束 ---------------------------------------

    def test_check_constraint_rejects_write_and_preserves_data(self):
        db_path = self.make_db("check_constraint.db", _CHECK_PERMISSION_SCHEMA)
        state_before = self.stored_state(db_path)
        self.assertEqual(
            state_before,
            (_CHECK_PERMISSION_SCHEMA, [("reader", PERMISSION_READ)]),
            f"测试前置：应只有 reader/documents:read 一条记录，实际为 {state_before!r}",
        )

        argv = ("grant", "reader", PERMISSION_WRITE)
        proc = self.run_rbac(*argv, db=db_path)
        self.assert_storage_error(proc, argv)

        # 原有授权与既有表结构保持不变。
        self.assertEqual(
            self.stored_state(db_path),
            state_before,
            f"grant 失败后表结构与数据不应变化，调用前为 {state_before!r}",
        )

        # 未被检查约束禁止的权限仍可正常授予。
        grant_result = self.assert_success_json(
            self.run_rbac("grant", "reader", "documents:list", db=db_path),
            "检查约束表上授予 documents:list",
        )
        self.assertEqual(
            grant_result,
            {"role": "reader", "permission": "documents:list"},
            f"grant 返回内容与预期不符，实际为 {grant_result!r}",
        )
        list_result = self.assert_success_json(
            self.run_rbac("list-permissions", "reader", db=db_path),
            "授予后列出 reader 的权限",
        )
        self.assertEqual(
            list_result,
            {"role": "reader", "permissions": ["documents:list", PERMISSION_READ]},
            f"list-permissions 结果与预期不符，实际为 {list_result!r}",
        )

    def test_check_constraint_existing_combo_is_idempotent_success(self):
        db_path = self.make_db("check_constraint.db", _CHECK_PERMISSION_SCHEMA)
        state_before = self.stored_state(db_path)

        result = self.assert_success_json(
            self.run_rbac("grant", "reader", PERMISSION_READ, db=db_path),
            "检查约束表上重复授予 reader/documents:read",
        )
        self.assertEqual(
            result,
            {"role": "reader", "permission": PERMISSION_READ},
            f"重复授予的返回内容与预期不符，实际为 {result!r}",
        )
        self.assertEqual(
            self.stored_state(db_path),
            state_before,
            f"幂等授予不应增加记录，调用前为 {state_before!r}",
        )

    # ---- 名称错误优先于存储失败 ------------------------------------------

    def test_blank_name_is_invalid_name_even_on_constraint_db(self):
        db_path = self.make_db("constraint.db", _UNIQUE_ROLE_SCHEMA)
        state_before = self.stored_state(db_path)

        cases = [
            ("grant", "", PERMISSION_WRITE),
            ("grant", "reader", "   "),
            ("grant", " \t\n ", PERMISSION_WRITE),
        ]
        for argv in cases:
            with self.subTest(argv=argv):
                proc = self.run_rbac(*argv, db=db_path)
                self.assertEqual(
                    proc.returncode,
                    2,
                    f"输入 {argv!r}：期望退出码 2，实际 {proc.returncode}，"
                    f"stdout={proc.stdout!r}，stderr={proc.stderr!r}",
                )
                self.assertEqual(
                    proc.stdout,
                    "",
                    f"输入 {argv!r}：invalid_name 时标准输出应为空，"
                    f"实际为 {proc.stdout!r}",
                )
                self.assertEqual(
                    proc.stderr,
                    INVALID_NAME_ERROR,
                    f"输入 {argv!r}：标准错误应为 {INVALID_NAME_ERROR!r}，"
                    f"实际为 {proc.stderr!r}",
                )

        self.assertEqual(
            self.stored_state(db_path),
            state_before,
            f"非法名称调用不应改变数据，调用前为 {state_before!r}",
        )

    # ---- 约束表上的其他命令保持既有行为 ----------------------------------

    def test_constraint_db_keeps_query_revoke_and_export_behavior(self):
        db_path = self.make_db("constraint.db", _UNIQUE_ROLE_SCHEMA)

        # 固定成员 alice 与 reader 的关系不变：预置授权使查询允许。
        check_result = self.assert_success_json(
            self.run_rbac("check", "alice", PERMISSION_READ, db=db_path),
            "约束表上查询 alice/documents:read",
        )
        self.assertEqual(
            check_result,
            {
                "member": "alice",
                "permission": PERMISSION_READ,
                "roles": ["reader"],
                "allowed": True,
                "reason": "直接角色授权",
            },
            f"check 结果与预期不符，实际为 {check_result!r}",
        )

        # export-rules 输出既有规则。
        export_result = self.assert_success_json(
            self.run_rbac("export-rules", db=db_path), "约束表上导出规则"
        )
        self.assertEqual(
            export_result,
            {"rules": [{"role": "reader", "permission": PERMISSION_READ}]},
            f"export-rules 结果与预期不符，实际为 {export_result!r}",
        )

        # revoke 既有授权正常生效。
        revoke_result = self.assert_success_json(
            self.run_rbac("revoke", "reader", PERMISSION_READ, db=db_path),
            "约束表上撤销 reader/documents:read",
        )
        self.assertEqual(
            revoke_result,
            {"role": "reader", "permission": PERMISSION_READ, "revoked": True},
            f"revoke 结果与预期不符，实际为 {revoke_result!r}",
        )
        self.assertEqual(
            self.stored_state(db_path),
            (_UNIQUE_ROLE_SCHEMA, []),
            f"撤销后授权记录应为空，实际为 {self.stored_state(db_path)!r}",
        )

    # ---- 标准规则库不受修复影响 ------------------------------------------

    def test_standard_rulebase_allows_read_and_write_for_same_role(self):
        # 父目录存在而规则文件缺失：创建标准规则库并正常授权。
        db_path = os.path.join(self.tmpdir, "rules.db")
        self.assertFalse(
            os.path.exists(db_path), "测试前置：规则文件应尚不存在"
        )

        for permission in (PERMISSION_READ, PERMISSION_WRITE):
            result = self.assert_success_json(
                self.run_rbac("grant", "reader", permission, db=db_path),
                f"标准规则库授予 reader/{permission}",
            )
            self.assertEqual(
                result,
                {"role": "reader", "permission": permission},
                f"grant 返回内容与预期不符，实际为 {result!r}",
            )

        list_result = self.assert_success_json(
            self.run_rbac("list-permissions", "reader", db=db_path),
            "标准规则库列出 reader 的权限",
        )
        self.assertEqual(
            list_result,
            {
                "role": "reader",
                "permissions": [PERMISSION_READ, PERMISSION_WRITE],
            },
            f"reader 应同时拥有读、写两项权限，实际为 {list_result!r}",
        )

        # 重复授予仍幂等，不增加记录。
        self.assert_success_json(
            self.run_rbac("grant", "reader", PERMISSION_READ, db=db_path),
            "标准规则库重复授予 reader/documents:read",
        )
        self.assertEqual(
            self.stored_state(db_path)[1],
            [("reader", PERMISSION_READ), ("reader", PERMISSION_WRITE)],
            f"重复授予后应仍只有两条记录，实际为 {self.stored_state(db_path)!r}",
        )


if __name__ == "__main__":
    unittest.main()
