"""rbac.store.list_permission_roles_for_roles 角色范围内来源映射的回归测试。

list-member-permissions --explain 展示授权来源时，用该函数在成员的直接
角色范围内汇总“权限 -> 直接获授该权限的角色列表”映射。本测试不经过
命令行子进程，直接传入角色列表调用存储层函数，使用独立临时 SQLite
样例核对来源映射语义。覆盖范围：

- 固定样例：reader 与 editor 都获授 documents:read，editor 另获授
  documents:write，viewer 获授 documents:read 与 private:read。查询
  ["editor", "reader", "editor", "missing"] 恰好返回
  {"documents:read": ["editor", "reader"],
   "documents:write": ["editor"]}：
  权限按 documents:read、documents:write 排列，来源角色精确且去重，
  viewer 不在入参范围内，其来源与 private:read 均不得出现；
- 交换角色顺序、去除重复角色、加入无授权角色，映射保持相同；
  调用不得改动入参列表；单独显式查询 viewer 时才能看到它的两条授权，
  以证明上面的隔离来自角色范围过滤而非样例缺失；
- 精确匹配：存储层不替调用方规整名称，单查大小写不同的 "Reader" 或
  带首尾空白的 " reader " 均返回 {}；角色名中的 "*"、"%"、"_" 仅为
  普通字符，只匹配同名角色，不存在 LIKE 式通配；没有对应规则时
  返回 {}，空角色列表直接返回 {}；
- 非 ASCII 权限名与来源角色名按完整名称的 Unicode 码点升序排列，
  名称原值保留（大小写、中文字符不转换）；
- 查询只读且结果稳定：同一连接上重复调用结果一致，查询前后全部授权
  行与 role_permissions 的表结构一致；
- 区分空结果与存储失败：现存 role_permissions 表只有 role 列、缺少
  permission 列并保留一行 reader 时，非空角色列表查询抛出
  rbac.store.StorageError，不能返回 {} 把失败伪装成空结果，也不得
  直接抛出 sqlite3 原始异常；空角色列表直接返回 {}；两种路径都不
  补列、不改动预置的 reader 行。

只依赖 Python 3 标准库与 SQLite；每个用例使用独立临时数据库文件，
连接在用例结束时关闭释放，临时数据随临时目录一起清理，不依赖任何
已有规则文件或其他用例的执行顺序。从项目根目录执行：

    python -m unittest discover -s tests
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
PERMISSION_PRIVATE = "private:read"

# 固定样例规则库：
# reader 持有 documents:read；
# editor 持有 documents:read、documents:write；
# viewer 持有 documents:read、private:read。
SEED_RULES = (
    ("reader", PERMISSION_READ),
    ("editor", PERMISSION_READ),
    ("editor", PERMISSION_WRITE),
    ("viewer", PERMISSION_READ),
    ("viewer", PERMISSION_PRIVATE),
)

# 查询 ["editor", "reader", "editor", "missing"] 的逐字期望：
# 权限按 Unicode 码点升序（documents:read < documents:write），
# documents:read 的来源恰为 editor 与 reader（码点升序、去重），
# documents:write 的来源恰为 editor；不出现 viewer 或 private:read。
EXPECTED_EDITOR_READER = {
    PERMISSION_READ: ["editor", "reader"],
    PERMISSION_WRITE: ["editor"],
}
EXPECTED_EDITOR_READER_KEY_ORDER = [PERMISSION_READ, PERMISSION_WRITE]

# 不兼容的表结构：只有 role 列，缺少 permission 列。
_INCOMPATIBLE_SCHEMA = "CREATE TABLE role_permissions (role TEXT)"


class PermissionRolesForRolesStoreTests(unittest.TestCase):
    """在固定样例规则库上核对角色范围内的来源映射语义。"""

    def setUp(self):
        # 每个用例独立的临时目录与数据库文件，TemporaryDirectory.cleanup
        # 负责清理；连接在用例结束时关闭释放。
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

    # ---- 辅助方法 -------------------------------------------------------

    def stored_rows(self):
        """直接读取 SQLite，返回排序后的 (role, permission) 全部授权行。"""
        return sorted(
            self.conn.execute(
                "SELECT role, permission FROM role_permissions"
            ).fetchall()
        )

    def schema_state(self):
        """返回 (role_permissions 的建表条目, 列定义, 全部授权行)。"""
        master = self.conn.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master "
            "WHERE name = 'role_permissions'"
        ).fetchall()
        columns = self.conn.execute(
            "PRAGMA table_info(role_permissions)"
        ).fetchall()
        return master, columns, self.stored_rows()

    def assert_mapping_equals(self, roles, expected, context):
        """核对映射结果，并验证重复调用稳定、只读且不改动入参列表。

        期望值由调用方以字面量给出，不借助被测函数计算。
        """
        roles_before = list(roles)
        rows_before = self.stored_rows()

        first = store.list_permission_roles_for_roles(self.conn, roles)
        second = store.list_permission_roles_for_roles(self.conn, list(roles))

        self.assertEqual(
            first,
            expected,
            f"{context}：输入 {roles!r}，期望 {expected!r}，实际为 {first!r}",
        )
        self.assertEqual(
            second,
            first,
            f"{context}：重复调用结果应稳定，输入 {roles!r}，"
            f"第一次 {first!r}，第二次 {second!r}",
        )
        self.assertEqual(
            roles,
            roles_before,
            f"{context}：调用不应改动入参角色列表，输入 {roles_before!r}，"
            f"调用后为 {roles!r}",
        )
        self.assertEqual(
            self.stored_rows(),
            rows_before,
            f"{context}：查询应为只读，输入 {roles!r}，查询前 {rows_before!r}，"
            f"查询后 {self.stored_rows()!r}",
        )
        return first

    # ---- 角色范围内的来源映射 -------------------------------------------

    def test_editor_reader_duplicates_missing_maps_exact_sources(self):
        roles = ["editor", "reader", "editor", "missing"]
        result = self.assert_mapping_equals(
            roles,
            EXPECTED_EDITOR_READER,
            "查询含重复角色与无授权角色的 [editor, reader, editor, missing]",
        )

        # 钉死权限键的排列顺序：documents:read 在前、documents:write 在后。
        self.assertEqual(
            list(result),
            EXPECTED_EDITOR_READER_KEY_ORDER,
            f"权限键应按 Unicode 码点升序排列，输入 {roles!r}，"
            f"期望顺序 {EXPECTED_EDITOR_READER_KEY_ORDER!r}，"
            f"实际顺序 {list(result)!r}",
        )
        # 每个权限的来源列表必非空、去重且按码点升序。
        for permission, source_roles in result.items():
            self.assertTrue(
                source_roles,
                f"{permission!r} 的来源列表不得为空，实际为 {source_roles!r}",
            )
            self.assertEqual(
                source_roles,
                sorted(source_roles),
                f"{permission!r} 的来源角色应按 Unicode 码点升序排列，"
                f"实际为 {source_roles!r}",
            )
            self.assertEqual(
                len(source_roles),
                len(set(source_roles)),
                f"{permission!r} 的来源角色不得重复，实际为 {source_roles!r}",
            )
        # 显式钉死范围隔离：viewer 不在入参中，其角色与 private:read
        # 都不得出现在映射里。
        self.assertNotIn(
            PERMISSION_PRIVATE,
            result,
            f"未查询 viewer 时 private:read 不得出现，输入 {roles!r}，"
            f"实际映射为 {result!r}",
        )
        all_sources = {role for source_roles in result.values() for role in source_roles}
        self.assertNotIn(
            "viewer",
            all_sources,
            f"viewer 不在入参角色范围内，不得成为来源，输入 {roles!r}，"
            f"实际来源合集 {sorted(all_sources)!r}",
        )

    def test_role_order_dedup_and_unauthorized_roles_keep_same_mapping(self):
        # 交换角色顺序、去除重复项、加入无授权角色：映射逐字相同，
        # 且每种输入列表调用后保持原值。
        variants = (
            ["reader", "editor", "editor", "missing"],
            ["editor", "reader", "missing"],
            ["missing", "reader", "editor"],
            ["editor", "reader", "missing", "ghost", "nobody"],
            ["ghost", "nobody", "reader", "editor", "reader"],
        )
        for roles in variants:
            with self.subTest(roles=roles):
                self.assert_mapping_equals(
                    roles,
                    EXPECTED_EDITOR_READER,
                    "角色顺序/重复/无授权角色不影响映射",
                )

    def test_viewer_visible_only_when_explicitly_in_scope(self):
        # viewer 的授权确实在样例库中：只有显式把 viewer 放入入参时，
        # 它与 private:read 才出现——证明主用例中的缺席是范围过滤。
        self.assert_mapping_equals(
            ["viewer"],
            {
                PERMISSION_READ: ["viewer"],
                PERMISSION_PRIVATE: ["viewer"],
            },
            "单独查询 viewer",
        )
        # viewer 与 editor/reader 同查时，documents:read 的来源为三者，
        # 顺序仍按完整角色名的 Unicode 码点：editor < reader < viewer。
        self.assert_mapping_equals(
            ["editor", "viewer", "reader"],
            {
                PERMISSION_READ: ["editor", "reader", "viewer"],
                PERMISSION_WRITE: ["editor"],
                PERMISSION_PRIVATE: ["viewer"],
            },
            "查询 [editor, viewer, reader]",
        )

    # ---- 精确匹配与空结果 ------------------------------------------------

    def test_case_mismatch_returns_empty_mapping(self):
        # 存储层大小写敏感：Reader 不是 reader，不贡献任何来源。
        self.assert_mapping_equals(
            ["Reader"], {}, "单查大小写不同的 Reader"
        )
        # 与 reader 混查时 Reader 既不匹配也不影响 reader 的结果。
        self.assert_mapping_equals(
            ["Reader", "reader"],
            {PERMISSION_READ: ["reader"]},
            "查询 [Reader, reader]",
        )

    def test_surrounding_whitespace_role_returns_empty_mapping(self):
        # 存储层不替调用方去除首尾空白：" reader " 是另一个不存在的角色名。
        for roles in ([" reader "], ["\treader\n"], [" reader", "reader "]):
            with self.subTest(roles=roles):
                self.assert_mapping_equals(
                    roles, {}, "带首尾空白的角色名应按原值精确匹配"
                )

    def test_unknown_role_and_empty_roles_return_empty_mapping(self):
        self.assert_mapping_equals(["missing"], {}, "单查无授权角色 missing")
        self.assert_mapping_equals([], {}, "查询空角色列表")
        # 重复与混排的无授权角色同样为空。
        self.assert_mapping_equals(
            ["missing", "ghost", "missing"], {}, "查询多个无授权角色"
        )

    # ---- 只读与稳定性 ----------------------------------------------------

    def test_repeated_calls_are_stable_and_leave_rows_and_schema_intact(self):
        roles = ["editor", "reader", "editor", "missing"]
        roles_copy = list(roles)
        state_before = self.schema_state()

        # 同一连接上连续调用（含不同输入），相同输入必须返回相同结果。
        first = store.list_permission_roles_for_roles(self.conn, roles)
        second = store.list_permission_roles_for_roles(self.conn, list(roles))
        third = store.list_permission_roles_for_roles(
            self.conn, ["reader", "editor", "missing"]
        )
        again = store.list_permission_roles_for_roles(self.conn, roles)

        self.assertEqual(
            second,
            first,
            f"同一连接重复调用结果应一致，输入 {roles!r}，"
            f"第一次 {first!r}，第二次 {second!r}",
        )
        self.assertEqual(
            third,
            first,
            f"去重与换序后的结果应与原输入一致，原输入 {roles!r}，"
            f"结果 {first!r}，换序后 {third!r}",
        )
        self.assertEqual(
            again,
            first,
            f"再次调用结果应一致，期望 {first!r}，实际为 {again!r}",
        )

        # 查询前后的全部授权行与表结构必须逐字一致。
        self.assertEqual(
            self.schema_state(),
            state_before,
            f"查询应为只读：查询前 {state_before!r}，"
            f"查询后 {self.schema_state()!r}",
        )
        # 入参列表不被调用改动。
        self.assertEqual(
            roles,
            roles_copy,
            f"调用不应改动入参角色列表，之前 {roles_copy!r}，之后 {roles!r}",
        )

    def test_mixed_queries_do_not_modify_seed_rules(self):
        # 执行各类查询后，完整授权行应与固定样例完全一致。
        for roles in (
            [],
            ["editor", "reader", "editor", "missing"],
            ["reader", "editor"],
            ["viewer"],
            ["Reader"],
            [" reader "],
            ["ghost", "nobody"],
        ):
            with self.subTest(roles=roles):
                store.list_permission_roles_for_roles(self.conn, roles)
        self.assertEqual(
            self.stored_rows(),
            sorted(SEED_RULES),
            f"全部查询后授权行应与固定样例一致，实际为 {self.stored_rows()!r}",
        )


class PermissionRolesForRolesWildcardTests(unittest.TestCase):
    """角色名中的 *、%、_ 按普通字符做完整名称精确匹配的小固定样例。"""

    # 角色名本身即通配字符；若实现误用 LIKE，"___"/"%%%" 等输入会误匹配。
    WILDCARD_RULES = (
        ("*", "p:star"),
        ("%", "p:pct"),
        ("_", "p:under"),
        ("a_b", "p:ab"),
    )

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.conn = store.connect(os.path.join(self._tmpdir.name, "rules.db"))
        self.addCleanup(self.conn.close)
        for role, permission in self.WILDCARD_RULES:
            self.assertTrue(
                store.grant_permission(self.conn, role, permission),
                f"测试前置：预置规则 {role}/{permission} 应实际新增",
            )

    def test_wildcard_named_roles_match_only_exact_same_name(self):
        # 一次查询四个通配字符角色名：键按 Unicode 码点升序
        # （p:ab < p:pct < p:star < p:under），来源恰为同名角色。
        roles = ["*", "%", "_", "a_b"]
        roles_before = list(roles)
        expected = {
            "p:ab": ["a_b"],
            "p:pct": ["%"],
            "p:star": ["*"],
            "p:under": ["_"],
        }
        result = store.list_permission_roles_for_roles(self.conn, roles)
        self.assertEqual(
            result,
            expected,
            f"通配字符角色名应精确匹配，输入 {roles!r}，"
            f"期望 {expected!r}，实际为 {result!r}",
        )
        self.assertEqual(
            list(result),
            ["p:ab", "p:pct", "p:star", "p:under"],
            f"权限键应按 Unicode 码点升序，实际顺序为 {list(result)!r}",
        )
        self.assertEqual(
            roles,
            roles_before,
            f"调用不应改动入参列表，之前 {roles_before!r}，之后 {roles!r}",
        )

        # 单个通配字符角色名单查：只返回它自己的授权。
        for role, permission in (
            ("*", "p:star"),
            ("%", "p:pct"),
            ("_", "p:under"),
            ("a_b", "p:ab"),
        ):
            with self.subTest(role=role):
                single = store.list_permission_roles_for_roles(self.conn, [role])
                self.assertEqual(
                    single,
                    {permission: [role]},
                    f"单查角色 {role!r}：期望 {{{permission!r}: [{role!r}]}}，"
                    f"实际为 {single!r}",
                )

    def test_like_style_patterns_do_not_match_wildcard_named_roles(self):
        # 若误用 LIKE：'_' 匹配任意单字符、'%' 匹配任意串、'a_b' 会被
        # 'aab' 命中。参数化精确等值查询下这些输入全部返回空映射。
        for roles in (
            ["aab"],
            ["___"],
            ["%%%"],
            ["**"],
            ["a%b"],
            ["a*b"],
            ["p:star"],
        ):
            with self.subTest(roles=roles):
                result = store.list_permission_roles_for_roles(self.conn, roles)
                self.assertEqual(
                    result,
                    {},
                    f"输入 {roles!r} 不应发生通配匹配，期望 {{}}，"
                    f"实际为 {result!r}",
                )

        # 全部查询后授权行仍为写入的四条。
        self.assertEqual(
            sorted(
                self.conn.execute(
                    "SELECT role, permission FROM role_permissions"
                ).fetchall()
            ),
            sorted(self.WILDCARD_RULES),
            "通配样例的查询应为只读，授权行与预置不符",
        )


class PermissionRolesForRolesUnicodeTests(unittest.TestCase):
    """非 ASCII 权限与来源角色按完整名称 Unicode 码点排序、原值保留。"""

    # 角色 A、a、中、reader 都获授 "読"；角色 a 另获授 A、a、中 三个权限。
    UNICODE_RULES = (
        ("A", "読"),
        ("a", "読"),
        ("中", "読"),
        ("reader", "読"),
        ("a", "A"),
        ("a", "a"),
        ("a", "中"),
    )

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.conn = store.connect(os.path.join(self._tmpdir.name, "rules.db"))
        self.addCleanup(self.conn.close)
        # 故意按与码点顺序不同的次序写入。
        for role, permission in self.UNICODE_RULES:
            self.assertTrue(
                store.grant_permission(self.conn, role, permission),
                f"测试前置：预置规则 {role}/{permission} 应实际新增",
            )

    def test_permissions_and_roles_sorted_by_codepoint_and_preserved(self):
        roles = ["reader", "中", "a", "A"]
        roles_before = list(roles)
        # 权限键码点序：A(0x41) < a(0x61) < 中(0x4E2D) < 読(0x8AAD)；
        # "読" 的来源角色码点序：A < a < reader(r=0x72) < 中。
        expected = {
            "A": ["a"],
            "a": ["a"],
            "中": ["a"],
            "読": ["A", "a", "reader", "中"],
        }
        result = store.list_permission_roles_for_roles(self.conn, roles)
        self.assertEqual(
            result,
            expected,
            f"非 ASCII 映射与预期不符，输入 {roles!r}，"
            f"期望 {expected!r}，实际为 {result!r}",
        )
        # 显式钉死权限键的排列顺序（dict 等值比较不检查键序）。
        self.assertEqual(
            list(result),
            ["A", "a", "中", "読"],
            f"权限键应按完整名称 Unicode 码点升序，实际顺序 {list(result)!r}",
        )
        # 来源角色同样按码点升序，且名称原值保留（大小写与中文字符不转换）。
        self.assertEqual(
            result["読"],
            ["A", "a", "reader", "中"],
            f"読 的来源角色应按码点升序且原值保留，实际为 {result['読']!r}",
        )
        self.assertEqual(
            roles,
            roles_before,
            f"调用不应改动入参列表，之前 {roles_before!r}，之后 {roles!r}",
        )

        # 同一连接重复调用结果一致，且授权行保持写入时的七条。
        self.assertEqual(
            store.list_permission_roles_for_roles(self.conn, list(roles)),
            result,
            "非 ASCII 样例重复调用结果应一致",
        )
        self.assertEqual(
            sorted(
                self.conn.execute(
                    "SELECT role, permission FROM role_permissions"
                ).fetchall()
            ),
            sorted(self.UNICODE_RULES),
            "非 ASCII 样例的查询应为只读，授权行与预置不符",
        )


class PermissionRolesForRolesIncompatibleSchemaTests(unittest.TestCase):
    """只有 role 列的现存规则表：存储失败与空列表短路必须明确区分。"""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.db_path = os.path.join(self._tmpdir.name, "rules.db")
        # 准备测试输入：表只有 role 列并保留一行 reader。
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(_INCOMPATIBLE_SCHEMA)
            conn.execute("INSERT INTO role_permissions (role) VALUES ('reader')")
        # connect 的 CREATE TABLE IF NOT EXISTS 对已有表为空操作，不补列。
        self.conn = store.connect(self.db_path)
        self.addCleanup(self.conn.close)

    def stored_state(self):
        """直接读取 SQLite，返回 (建表语句, 列定义, 全部行)。"""
        schema = self.conn.execute(
            "SELECT sql FROM sqlite_master WHERE name = 'role_permissions'"
        ).fetchone()[0]
        columns = self.conn.execute(
            "PRAGMA table_info(role_permissions)"
        ).fetchall()
        rows = sorted(self.conn.execute("SELECT role FROM role_permissions").fetchall())
        return schema, columns, rows

    def assert_state_unchanged(self, state_before, context):
        """调用后列定义与 reader 行应与调用前一致：不补列、不改记录。"""
        state_after = self.stored_state()
        self.assertEqual(
            state_after,
            state_before,
            f"{context}：调用后表结构或数据发生变化，调用前 {state_before!r}，"
            f"调用后为 {state_after!r}",
        )
        # 显式钉死：列定义里不得新增 permission 列。
        self.assertEqual(
            [column[1] for column in state_after[1]],
            ["role"],
            f"{context}：列定义应仍只有 role，"
            f"实际为 {[column[1] for column in state_after[1]]!r}",
        )
        # 显式钉死：预置的 reader 行既不被删除，也不被补写。
        self.assertEqual(
            state_after[2],
            [("reader",)],
            f"{context}：reader 数据应保持不变，实际为 {state_after[2]!r}",
        )

    def test_non_empty_roles_raise_storage_error(self):
        state_before = self.stored_state()
        self.assertEqual(
            state_before,
            (_INCOMPATIBLE_SCHEMA, [(0, "role", "TEXT", 0, None, 0)], [("reader",)]),
            f"测试前置：表应只有 role 列并保留一行 reader，"
            f"实际为 {state_before!r}",
        )

        # 非空角色列表必须查询 permission 列：缺列导致存储失败，
        # 应抛出 rbac.store.StorageError，而非返回 {} 把失败伪装成空结果。
        with self.assertRaises(
            store.StorageError,
            msg="缺少 permission 列时非空角色列表查询应抛出 StorageError",
        ) as assertion_context:
            store.list_permission_roles_for_roles(self.conn, ["reader"])

        # 不得直接向外抛出 sqlite3 原始异常：StorageError 不是 sqlite3.Error，
        # 底层 sqlite3 错误经 __cause__ 包装而非直通。
        raised = assertion_context.exception
        self.assertNotIsInstance(
            raised,
            sqlite3.Error,
            f"对外抛出的应是包装后的 StorageError，而非 sqlite3 原始异常，"
            f"实际类型为 {type(raised).__name__}",
        )
        self.assertIsInstance(
            raised.__cause__,
            sqlite3.Error,
            "StorageError 应包装底层 sqlite3 错误（__cause__），"
            f"实际 __cause__ 为 {raised.__cause__!r}",
        )

        self.assert_state_unchanged(state_before, "非空角色列表查询失败后")

    def test_several_non_empty_role_inputs_all_raise_storage_error(self):
        # 表中的 reader 行与不在表中的角色没有区别：只要查询 permission 列
        # 就必然失败；重复角色同样失败，且失败不应抛出 sqlite3 原始异常。
        for roles in (
            ["editor"],
            ["reader", "editor"],
            ["missing"],
            ["reader", "reader"],
        ):
            with self.subTest(roles=roles):
                with self.assertRaises(store.StorageError) as assertion_context:
                    store.list_permission_roles_for_roles(self.conn, roles)
                self.assertNotIsInstance(
                    assertion_context.exception,
                    sqlite3.Error,
                    f"输入 {roles!r}：应抛出包装后的 StorageError",
                )

        # 全部失败尝试后仍只有预置的一行 reader，列定义不变。
        self.assertEqual(
            self.stored_state(),
            (_INCOMPATIBLE_SCHEMA, [(0, "role", "TEXT", 0, None, 0)], [("reader",)]),
            f"多次失败后表结构与数据应保持不变，实际为 {self.stored_state()!r}",
        )

    def test_empty_roles_on_incompatible_schema_returns_empty_mapping(self):
        state_before = self.stored_state()

        # 空角色列表短路返回空映射而不触碰规则表：同一连接上缺列不影响此结果。
        result = store.list_permission_roles_for_roles(self.conn, [])
        self.assertEqual(
            result,
            {},
            f"空角色列表应返回 {{}}，即使规则表缺少 permission 列，"
            f"实际为 {result!r}",
        )

        self.assert_state_unchanged(state_before, "空角色列表查询后")

    def test_failure_and_empty_result_both_leave_state_unchanged(self):
        # 在同一连接上先触发存储失败、再走空列表的正常空结果：
        # 两种路径都不得补列或改动预置数据，且空结果路径不被前次失败污染。
        state_before = self.stored_state()

        with self.assertRaises(store.StorageError):
            store.list_permission_roles_for_roles(self.conn, ["reader"])
        self.assert_state_unchanged(state_before, "存储失败后")

        self.assertEqual(
            store.list_permission_roles_for_roles(self.conn, []),
            {},
            "存储失败后，空角色列表查询仍应返回 {}",
        )
        self.assert_state_unchanged(state_before, "随后空角色列表查询后")

        # 再次以非空角色查询仍应失败：空列表的成功调用不修复任何东西。
        with self.assertRaises(store.StorageError):
            store.list_permission_roles_for_roles(self.conn, ["reader"])
        self.assert_state_unchanged(state_before, "再次存储失败后")


if __name__ == "__main__":
    unittest.main()
