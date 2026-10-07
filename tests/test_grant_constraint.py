"""既有表约束阻止 grant 写入时的回归测试。

背景：grant 曾用 INSERT OR IGNORE 写入规则，既有表上的唯一约束或检查
约束拒绝新增行时会被该子句一并吞掉，命令在规则并未持久保存时仍报告
成功。修复后的语义：

- 名称规整后（角色, 权限）完整组合已存在：按幂等成功处理（退出码 0，
  返回现有 role、permission JSON，标准错误为空），不增加记录；
- 组合不存在：只有目标规则实际持久保存才算成功；既有表的唯一约束或
  检查约束阻止新增规则时返回存储失败——退出码 1，标准输出为空，
  标准错误恰为 {"error":"storage_error"} 加一个换行；原有授权、其他表
  与既有表结构保持不变。

验收固定样例（独立 constraint.db，手工执行同样适用）：

    CREATE TABLE role_permissions (
        role       TEXT NOT NULL UNIQUE,
        permission TEXT NOT NULL
    );
    -- 仅预置一行 (reader, documents:read)
    python -m rbac --db constraint.db grant reader documents:write
        -> 退出码 1，stdout 为空，stderr 为 {"error":"storage_error"}\\n
    python -m rbac --db constraint.db list-permissions reader
        -> 退出码 0，{"role":"reader","permissions":["documents:read"]}
    再次授予已有的 documents:read：仍成功且不增加记录。

另补充 permission 列带 CHECK(permission <> 'documents:write') 的固定
样例，核对同样的拒绝结果与原数据保留；并验证标准规则库（复合主键）
仍允许 reader 同时拥有 documents:read、documents:write 两项权限。

只依赖 Python 3 标准库与 SQLite；每个用例使用独立临时目录，结束后
自动清理。从项目根目录执行：

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

# 验收样例：role 列带单列唯一约束（与标准库的复合主键不同）。
_UNIQUE_ROLE_SCHEMA = (
    "CREATE TABLE role_permissions ("
    "role TEXT NOT NULL UNIQUE, permission TEXT NOT NULL)"
)

# 补充固定样例：permission 列带检查约束，禁止写入 documents:write。
_CHECK_PERMISSION_SCHEMA = (
    "CREATE TABLE role_permissions ("
    "role TEXT NOT NULL, permission TEXT NOT NULL, "
    "CHECK(permission <> 'documents:write'))"
)


class GrantConstraintTests(unittest.TestCase):
    """通过 `python -m rbac` 子进程核对约束阻止写入时的对外行为。"""

    def setUp(self):
        # 每个用例独立的临时目录，TemporaryDirectory.cleanup 负责清理。
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.tmpdir = self._tmpdir.name
        self.db_path = os.path.join(self.tmpdir, "constraint.db")

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

    def list_permissions(self, role, **kwargs):
        return self.run_rbac("list-permissions", role, **kwargs)

    def prepare(self, schema):
        """按给定表结构建库，仅预置 (reader, documents:read) 一行。"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(schema)
            conn.execute(
                "INSERT INTO role_permissions (role, permission) "
                "VALUES ('reader', ?)",
                (PERMISSION_READ,),
            )

    def stored_state(self):
        """直接读取 SQLite，返回 (建表语句, 排序后的全部行, 表名集合)。

        同时取表名集合以核对其他表不受影响。
        """
        with sqlite3.connect(self.db_path) as conn:
            schema = conn.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' "
                "AND name = 'role_permissions'"
            ).fetchone()[0]
            rows = sorted(
                conn.execute(
                    "SELECT role, permission FROM role_permissions"
                ).fetchall()
            )
            tables = sorted(
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            )
        return schema, rows, tables

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
            f"输入 {argv!r}：storage_error 时标准输出应为空（不得夹带成功的"
            f" role/permission JSON），实际为 {proc.stdout!r}",
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
            f"{context}：标准输出应恰为单个 JSON 对象加一个换行，"
            f"实际为 {proc.stdout!r}",
        )
        return json.loads(proc.stdout[:-1])

    # ---- 验收样例：单列唯一约束 ------------------------------------------

    def test_unique_role_constraint_rejects_new_permission_with_storage_error(self):
        # 独立 constraint.db，单列 role UNIQUE，仅预置 reader/documents:read。
        self.prepare(_UNIQUE_ROLE_SCHEMA)
        state_before = self.stored_state()
        self.assertEqual(
            state_before[1],
            [("reader", PERMISSION_READ)],
            f"测试前置：应只预置 reader/{PERMISSION_READ}，实际为 {state_before[1]!r}",
        )

        # 组合 (reader, documents:write) 不存在，但同一 reader 违反单列
        # 唯一约束：必须按存储失败处理，而非 INSERT OR IGNORE 式的假成功。
        argv = ("grant", "reader", PERMISSION_WRITE)
        self.assert_storage_error(self.run_rbac(*argv), argv)

        # 原有授权、其他表与既有表结构保持不变。
        self.assertEqual(
            self.stored_state(),
            state_before,
            f"约束拒绝后表结构、数据与其他表均不应变化，调用前 {state_before!r}，"
            f"调用后 {self.stored_state()!r}",
        )

    def test_acceptance_sequence_unique_role_db(self):
        """完整复现验收：拒绝写入 -> 列出仍为 read -> 重复授 read 幂等。"""
        self.prepare(_UNIQUE_ROLE_SCHEMA)

        # 1) 被单列唯一约束拒绝。
        self.assert_storage_error(
            self.grant("reader", PERMISSION_WRITE),
            ("grant", "reader", PERMISSION_WRITE),
        )

        # 2) 同库 list-permissions reader 仍只输出 documents:read，退出码 0。
        listed = self.assert_success_json(
            self.list_permissions("reader"), "拒绝写入后列出 reader 的权限"
        )
        self.assertEqual(
            listed,
            {"role": "reader", "permissions": [PERMISSION_READ]},
            f"list-permissions 应保留原数据且仅含 {PERMISSION_READ}，"
            f"实际为 {listed!r}",
        )

        # 3) 完整组合已存在：再次授予 documents:read 仍按幂等成功处理，
        #    标准错误为空，且不增加记录。
        regrant = self.assert_success_json(
            self.grant("reader", PERMISSION_READ), "重复授予已有组合"
        )
        self.assertEqual(
            regrant,
            {"role": "reader", "permission": PERMISSION_READ},
            f"幂等授予应返回现有 role、permission JSON，实际为 {regrant!r}",
        )
        self.assertEqual(
            self.stored_state()[1],
            [("reader", PERMISSION_READ)],
            f"幂等授予不应增加记录，实际为 {self.stored_state()[1]!r}",
        )

    def test_unique_role_constraint_allows_distinct_role(self):
        # 约束针对 role 单列：组合 (editor, documents:read) 不存在且不冲突，
        # 必须真正持久保存才算成功。
        self.prepare(_UNIQUE_ROLE_SCHEMA)
        result = self.assert_success_json(
            self.grant("editor", PERMISSION_READ), "授予另一角色 editor"
        )
        self.assertEqual(
            result,
            {"role": "editor", "permission": PERMISSION_READ},
            f"不触发约束的新组合应成功，实际为 {result!r}",
        )
        self.assertEqual(
            self.stored_state()[1],
            [("editor", PERMISSION_READ), ("reader", PERMISSION_READ)],
            f"新规则应实际持久保存，实际为 {self.stored_state()[1]!r}",
        )

    # ---- 补充样例：CHECK 检查约束 ----------------------------------------

    def test_check_constraint_rejects_forbidden_permission(self):
        # permission 列带 CHECK(permission <> 'documents:write')，
        # 预置的 documents:read 不违反检查约束。
        self.prepare(_CHECK_PERMISSION_SCHEMA)
        state_before = self.stored_state()

        argv = ("grant", "reader", PERMISSION_WRITE)
        self.assert_storage_error(self.run_rbac(*argv), argv)

        # 同样的拒绝结果与原数据保留。
        self.assertEqual(
            self.stored_state(),
            state_before,
            f"CHECK 拒绝后表结构与数据不应变化，调用前 {state_before!r}，"
            f"调用后 {self.stored_state()!r}",
        )

        # 检查约束不阻止另一角色获得允许范围内的权限：真实持久保存。
        granted = self.assert_success_json(
            self.grant("editor", PERMISSION_READ), "授予 editor/documents:read"
        )
        self.assertEqual(
            granted,
            {"role": "editor", "permission": PERMISSION_READ},
            f"不违反 CHECK 的新组合应成功，实际为 {granted!r}",
        )
        self.assertEqual(
            self.stored_state()[1],
            [("editor", PERMISSION_READ), ("reader", PERMISSION_READ)],
            f"新规则应实际持久保存，实际为 {self.stored_state()[1]!r}",
        )

    def test_check_constraint_idempotent_on_existing_combination(self):
        self.prepare(_CHECK_PERMISSION_SCHEMA)
        # 已存在的 (reader, documents:read) 即使在带 CHECK 的表上也按
        # 幂等成功处理，不增加记录，也不会触发检查约束。
        result = self.assert_success_json(
            self.grant("reader", PERMISSION_READ), "重复授予已有组合"
        )
        self.assertEqual(
            result,
            {"role": "reader", "permission": PERMISSION_READ},
            f"幂等授予应返回现有组合，实际为 {result!r}",
        )
        self.assertEqual(
            self.stored_state()[1],
            [("reader", PERMISSION_READ)],
            f"幂等授予不应增加记录，实际为 {self.stored_state()[1]!r}",
        )

    # ---- 标准规则库：复合主键下读、写可并存 --------------------------------

    def test_standard_rulebase_allows_reader_read_and_write(self):
        # 不预置任何表：父目录存在、规则文件缺失时应创建标准规则库
        # （复合主键 (role, permission)），reader 可同时拥有读、写两项。
        self.assertFalse(
            os.path.exists(self.db_path), "测试前置：标准规则库文件应尚未创建"
        )
        read_result = self.assert_success_json(
            self.grant("reader", PERMISSION_READ), "标准库授予 documents:read"
        )
        self.assertEqual(
            read_result,
            {"role": "reader", "permission": PERMISSION_READ},
            f"首次授予应成功，实际为 {read_result!r}",
        )
        write_result = self.assert_success_json(
            self.grant("reader", PERMISSION_WRITE), "标准库授予 documents:write"
        )
        self.assertEqual(
            write_result,
            {"role": "reader", "permission": PERMISSION_WRITE},
            f"复合主键下同一角色的不同权限应能并存，实际为 {write_result!r}",
        )

        listed = self.assert_success_json(
            self.list_permissions("reader"), "列出 reader 的读、写两项权限"
        )
        self.assertEqual(
            listed,
            {"role": "reader", "permissions": [PERMISSION_READ, PERMISSION_WRITE]},
            f"标准规则库应允许 reader 同时拥有读、写权限，实际为 {listed!r}",
        )

        # 标准表结构确为复合主键（修复不改变既有建表结构）。
        schema = self.stored_state()[0]
        self.assertIn(
            "PRIMARY KEY (role, permission)",
            schema,
            f"标准规则库应保持复合主键结构，实际建表语句为 {schema!r}",
        )


if __name__ == "__main__":
    unittest.main()
