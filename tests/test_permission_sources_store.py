"""rbac.store.list_permission_sources_for_roles 权限来源映射的回归测试。

list-member-permissions --explain 用该函数一次查出成员全部直接角色的
获授权限及每项权限的来源角色。本测试不经过命令行子进程，直接传入角色
列表调用存储层函数，使用真实 SQLite 数据核对来源语义。覆盖范围：

- 多角色各自获授与共享权限：reader 获授 documents:read、documents:write，
  editor 获授 documents:read、reports:export，查询 ["reader", "editor"]
  返回按权限名 Unicode 码点升序的映射，共享权限 documents:read 的来源为
  ["editor", "reader"]，不混入未查询角色 ghost 的权限；
- 单角色与去重：重复授予、重复角色入参不产生重复来源；
- 空角色列表与全部未获授权角色返回空字典，且不触碰规则表；
  大小写敏感：Reader 不是 reader；
- 名称原样保留、权限与角色分别按完整名称 Unicode 码点升序；查询只读；
- 缺 permission 列的现存表：非空角色查询抛出 rbac.store.StorageError，
  空角色列表仍返回空字典，均不补列、不改预置数据。

只依赖 Python 3 标准库与 SQLite；每个用例使用独立临时数据库文件。
从项目根目录执行：

    python -m unittest discover -s tests -p test_permission_sources_store.py
"""

import os
import sqlite3
import sys
import tempfile
import unittest

# tests/ 的上一级即项目根目录（rbac 包所在目录）。
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from rbac import store

PERMISSION_READ = "documents:read"
PERMISSION_WRITE = "documents:write"
PERMISSION_EXPORT = "reports:export"
PERMISSION_PRIVATE = "private:read"

# reader 持有 documents:read、documents:write；
# editor 持有 documents:read、reports:export（与 reader 共享 read）；
# ghost 持有 private:read，且 ghost 未关联任何固定成员。
SEED_RULES = (
    ("reader", PERMISSION_READ),
    ("reader", PERMISSION_WRITE),
    ("editor", PERMISSION_READ),
    ("editor", PERMISSION_EXPORT),
    ("ghost", PERMISSION_PRIVATE),
)

_INCOMPATIBLE_SCHEMA = "CREATE TABLE role_permissions (role TEXT)"


class PermissionSourcesForRolesTests(unittest.TestCase):
    """在固定样例规则库上核对权限 -> 来源角色映射语义。"""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.db_path = os.path.join(self._tmpdir.name, "rules.db")
        self.conn = store.connect(self.db_path)
        self.addCleanup(self.conn.close)
        for role, permission in SEED_RULES:
            self.assertTrue(
                store.grant_permission(self.conn, role, permission),
                f"测试前置：预置规则 {role}/{permission} 应实际新增",
            )

    def stored_rules(self):
        return sorted(
            self.conn.execute(
                "SELECT role, permission FROM role_permissions"
            ).fetchall()
        )

    def test_reader_editor_sources_are_exact_and_sorted(self):
        result = store.list_permission_sources_for_roles(
            self.conn, ["reader", "editor"]
        )
        expected = {
            PERMISSION_READ: ["editor", "reader"],
            PERMISSION_WRITE: ["reader"],
            PERMISSION_EXPORT: ["editor"],
        }
        self.assertEqual(result, expected, f"实际为 {result!r}")
        # 权限按完整名称 Unicode 码点升序（dict 按插入顺序保留该顺序）。
        self.assertEqual(list(result.keys()), sorted(result.keys()))
        # 每个权限的来源角色去重、非空、按角色名码点升序。
        for permission, roles in result.items():
            self.assertTrue(roles, f"{permission} 不应有空来源")
            self.assertEqual(roles, sorted(roles))
            self.assertEqual(len(roles), len(set(roles)))
        # 未查询 ghost：其权限不得混入。
        self.assertNotIn(PERMISSION_PRIVATE, result)

    def test_single_role_and_duplicate_inputs(self):
        self.assertEqual(
            store.list_permission_sources_for_roles(self.conn, ["reader"]),
            {PERMISSION_READ: ["reader"], PERMISSION_WRITE: ["reader"]},
        )
        # 角色入参重复不产生重复来源；角色顺序不影响结果。
        self.assertEqual(
            store.list_permission_sources_for_roles(
                self.conn, ["editor", "reader", "editor"]
            ),
            {
                PERMISSION_READ: ["editor", "reader"],
                PERMISSION_WRITE: ["reader"],
                PERMISSION_EXPORT: ["editor"],
            },
        )

    def test_empty_and_unauthorized_roles_return_empty_dict(self):
        self.assertEqual(store.list_permission_sources_for_roles(self.conn, []), {})
        self.assertEqual(
            store.list_permission_sources_for_roles(
                self.conn, ["stranger", "nobody"]
            ),
            {},
        )

    def test_role_matching_is_case_sensitive(self):
        self.assertEqual(
            store.list_permission_sources_for_roles(self.conn, ["Reader"]), {}
        )

    def test_names_preserved_and_sorted_by_unicode_codepoint(self):
        unicode_db = os.path.join(self._tmpdir.name, "unicode_rules.db")
        conn = store.connect(unicode_db)
        self.addCleanup(conn.close)
        # 两个角色名码点顺序与插入顺序不同；权限同样乱序写入。
        for role, permission in (
            ("中", "中"),
            ("a", "A"),
            ("A", "a"),
            ("A", "中"),
        ):
            store.grant_permission(conn, role, permission)

        result = store.list_permission_sources_for_roles(conn, ["A", "a", "中"])
        # 权限顺序：A < a < 中；"中" 的来源角色：A(0x41) < 中(0x4E2D)。
        self.assertEqual(
            result,
            {
                "A": ["a"],
                "a": ["A"],
                "中": ["A", "中"],
            },
            f"名称原样保留与码点排序不符，实际为 {result!r}",
        )

    def test_query_is_read_only_and_stable(self):
        roles = ["reader", "editor"]
        first = store.list_permission_sources_for_roles(self.conn, roles)
        second = store.list_permission_sources_for_roles(self.conn, roles)
        self.assertEqual(first, second)
        self.assertEqual(self.stored_rules(), sorted(SEED_RULES))

    def test_keys_equal_list_permissions_for_roles(self):
        # permissions 合集与来源映射必须来自同一口径：键集合即权限列表。
        for roles in ([], ["reader"], ["editor", "reader"], ["ghost"]):
            with self.subTest(roles=roles):
                sources = store.list_permission_sources_for_roles(self.conn, roles)
                self.assertEqual(
                    list(sources.keys()),
                    store.list_permissions_for_roles(self.conn, roles),
                )


class PermissionSourcesIncompatibleSchemaTests(unittest.TestCase):
    """缺少 permission 列的现存规则表：来源查询同样区分失败与空结果。"""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.db_path = os.path.join(self._tmpdir.name, "rules.db")
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(_INCOMPATIBLE_SCHEMA)
            conn.execute("INSERT INTO role_permissions (role) VALUES ('reader')")
        self.conn = store.connect(self.db_path)
        self.addCleanup(self.conn.close)

    def test_non_empty_roles_raise_storage_error(self):
        with self.assertRaises(store.StorageError):
            store.list_permission_sources_for_roles(self.conn, ["reader"])

    def test_empty_roles_return_empty_dict_without_touching_table(self):
        self.assertEqual(
            store.list_permission_sources_for_roles(self.conn, []), {}
        )
        # 不补列、reader 行不变。
        columns = [
            row[1]
            for row in self.conn.execute(
                "PRAGMA table_info(role_permissions)"
            ).fetchall()
        ]
        self.assertEqual(columns, ["role"])
        self.assertEqual(
            self.conn.execute("SELECT role FROM role_permissions").fetchall(),
            [("reader",)],
        )


if __name__ == "__main__":
    unittest.main()
