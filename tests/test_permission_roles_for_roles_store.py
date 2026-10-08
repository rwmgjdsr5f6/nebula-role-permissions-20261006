"""rbac.store.list_permission_roles_for_roles 角色范围内来源映射的回归测试。

list-member-permissions --explain 展示每项权限的授权来源时，用该函数对
成员的直接角色汇总“权限 -> 直接获授该权限的角色列表”映射。多角色重叠
获授同一项权限的来源聚合无法经公开命令行构造（固定配置当前只有
alice -> reader），因此本测试不经过命令行子进程，直接传入角色列表调用
存储层函数，使用真实 SQLite 数据核对来源映射语义。覆盖范围：

- 固定样例：reader 与 editor 都获授 documents:read，editor 另有
  documents:write，viewer 另有 documents:read 与 private:read；
  输入 ["editor", "reader", "editor", "missing"] 时映射只含
  documents:read -> ["editor", "reader"]、documents:write -> ["editor"]，
  viewer 与 private:read 不出现；权限键与来源角色均按 Unicode 码点升序；
- 交换角色顺序、去除重复角色、混入从未获授权的角色，映射保持相同，
  调用方传入的角色列表不被修改；
- 精确匹配：存储层不替调用方规整名称，单独输入 "Reader" 或带首尾空白的
  " reader " 均返回 {}（样例中没有同名角色，也不存在名为空串的角色）；
  角色名中的 "*"、"%"、"_" 均为普通字符，只匹配同名角色，无对应规则时
  返回 {}；
- 名称原样保留与 Unicode 码点排序：非 ASCII 权限和来源角色按完整名称的
  码点升序排列，名称原值保留（大小写、中文不转换）；
- 查询只读且结果稳定：同一连接上重复调用结果一致，查询前后完整授权
  记录与表结构均不变化；
- 区分空结果与存储失败：现存 role_permissions 表只有 role 列、缺少
  permission 列并保存一行 reader 时，非空角色列表查询抛出
  rbac.store.StorageError，不能返回 {}，也不得直接抛出 sqlite3 原始
  异常；同一连接传入空角色列表仍返回 {}（空路径不查规则表）；两种路径
  均不补列、不改动原有行。

只依赖 Python 3 标准库与 SQLite；每个用例使用独立临时数据库文件，
连接在用例结束时关闭释放，临时目录由 TemporaryDirectory 自动清理，
不依赖任何已有规则文件或其他用例的执行顺序。从项目根目录执行：

    python -m unittest discover -s tests -p test_permission_roles_for_roles_store.py
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
# editor 持有 documents:read、documents:write（与 reader 共享 read）；
# viewer 持有 documents:read、private:read，但不进入下列查询的角色范围。
SEED_RULES = (
    ("reader", PERMISSION_READ),
    ("editor", PERMISSION_READ),
    ("editor", PERMISSION_WRITE),
    ("viewer", PERMISSION_READ),
    ("viewer", PERMISSION_PRIVATE),
)

# 主样例输入与期望（期望值直接来自上面的固定样例，逐字写出，
# 不借助被测函数计算；documents:read < documents:write，
# editor < reader，均为完整名称的 Unicode 码点顺序）。
SAMPLE_ROLES = ["editor", "reader", "editor", "missing"]
SAMPLE_EXPECTED = {
    PERMISSION_READ: ["editor", "reader"],
    PERMISSION_WRITE: ["editor"],
}

# 不兼容的表结构：只有 role 列，缺少 permission 列。
_INCOMPATIBLE_SCHEMA = "CREATE TABLE role_permissions (role TEXT)"


class PermissionRolesForRolesTests(unittest.TestCase):
    """在固定样例规则库上核对角色范围内的权限来源映射。"""

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

    def stored_rules(self):
        """直接读取 SQLite，返回排序后的 (role, permission) 授权记录。"""
        return sorted(
            self.conn.execute(
                "SELECT role, permission FROM role_permissions"
            ).fetchall()
        )

    def assert_mapping(self, roles, expected, context):
        """核对来源映射，并验证查询只读、结果稳定、不改动角色输入。

        同一查询在同一连接上连续执行两次，结果必须一致；调用前后完整
        授权记录与调用方持有的角色列表均不得变化。
        """
        roles_before = list(roles)
        rules_before = self.stored_rules()

        first = store.list_permission_roles_for_roles(self.conn, roles)
        second = store.list_permission_roles_for_roles(self.conn, roles)

        self.assertEqual(
            first,
            expected,
            f"{context}：输入 {roles!r}，期望 {expected!r}，实际为 {first!r}",
        )
        self.assertEqual(
            second,
            first,
            f"{context}：重复调用结果应稳定，第一次 {first!r}，"
            f"第二次 {second!r}",
        )
        self.assertEqual(
            roles,
            roles_before,
            f"{context}：调用不应改动角色输入，之前 {roles_before!r}，"
            f"之后 {roles!r}",
        )
        self.assertEqual(
            self.stored_rules(),
            rules_before,
            f"{context}：查询不应改动授权记录，之前 {rules_before!r}，"
            f"之后 {self.stored_rules()!r}",
        )

    # ---- 固定样例：精确的范围来源映射 -----------------------------------

    def test_sample_mapping_is_exact_and_scoped_to_input_roles(self):
        result = store.list_permission_roles_for_roles(self.conn, SAMPLE_ROLES)

        # 与逐字写出的期望完全一致：键顺序、来源顺序、值内容同时钉死。
        self.assertEqual(
            result,
            SAMPLE_EXPECTED,
            f"输入 {SAMPLE_ROLES!r}：期望 {SAMPLE_EXPECTED!r}，"
            f"实际为 {result!r}",
        )

        # 钉死 documents:read 的来源恰为 editor、reader（去重、码点升序）。
        self.assertEqual(
            result.get(PERMISSION_READ),
            ["editor", "reader"],
            f"documents:read 的来源应恰为 editor、reader，实际为 {result!r}",
        )
        # 钉死 documents:write 的来源恰为 editor。
        self.assertEqual(
            result.get(PERMISSION_WRITE),
            ["editor"],
            f"documents:write 的来源应恰为 editor，实际为 {result!r}",
        )

        # viewer 不在入参角色范围内：即使它同样获授 documents:read，
        # 也不得出现在任何来源列表中；其 private:read 不得产生条目。
        self.assertNotIn(
            PERMISSION_PRIVATE,
            result,
            f"未查询 viewer 时不得出现 private:read 条目，实际为 {result!r}",
        )
        for permission, source_roles in result.items():
            self.assertNotIn(
                "viewer",
                source_roles,
                f"{permission} 的来源不得包含范围外的 viewer，实际为 {result!r}",
            )

        # 钉死“恰好”两项，且每项来源非空、无重复。
        self.assertEqual(
            list(result),
            [PERMISSION_READ, PERMISSION_WRITE],
            f"映射应恰含 documents:read、documents:write 两项"
            f"（按码点升序），实际为 {list(result)!r}",
        )
        for permission, source_roles in result.items():
            self.assertTrue(
                source_roles,
                f"{permission} 的来源列表不应为空，实际为 {result!r}",
            )
            self.assertEqual(
                len(source_roles),
                len(set(source_roles)),
                f"{permission} 的来源角色不应重复，实际为 {source_roles!r}",
            )
            self.assertEqual(
                source_roles,
                sorted(source_roles),
                f"{permission} 的来源角色应按 Unicode 码点升序排列，"
                f"实际为 {source_roles!r}",
            )

        # 对照：viewer 与 private:read 确实在样例库中，不出现是范围隔离，
        # 而非授权未写入。
        self.assertEqual(
            self.stored_rules(),
            sorted(SEED_RULES),
            f"测试前置：样例授权应全部在库（含 viewer），"
            f"实际为 {self.stored_rules()!r}",
        )

    def test_role_order_duplicates_and_unauthorized_roles_keep_same_mapping(self):
        # 交换角色顺序：editor/reader 的先后不影响键与来源的码点排序。
        self.assert_mapping(
            ["reader", "editor"],
            SAMPLE_EXPECTED,
            "交换角色顺序 [reader, editor]",
        )
        # 去除重复项。
        self.assert_mapping(
            ["editor", "reader"],
            SAMPLE_EXPECTED,
            "去除重复项 [editor, reader]",
        )
        # 主样例本身（含重复 editor 与未授权角色 missing）。
        self.assert_mapping(
            list(SAMPLE_ROLES),
            SAMPLE_EXPECTED,
            "主样例 [editor, reader, editor, missing]",
        )
        # 加入多个从未获授权的角色并重复、混排。
        self.assert_mapping(
            ["missing", "reader", "nobody", "editor", "stranger", "reader"],
            SAMPLE_EXPECTED,
            "混入多个无授权角色并重复 [missing, reader, nobody, editor, "
            "stranger, reader]",
        )

    def test_single_scoped_role_returns_only_its_own_sources(self):
        # 单查 editor：两项权限的来源都只有 editor。
        self.assert_mapping(
            ["editor"],
            {
                PERMISSION_READ: ["editor"],
                PERMISSION_WRITE: ["editor"],
            },
            "单查 editor",
        )
        # 单查 reader：只贡献 documents:read，不产生 documents:write。
        self.assert_mapping(
            ["reader"],
            {PERMISSION_READ: ["reader"]},
            "单查 reader",
        )
        # 单查 viewer（本用例显式把它纳入范围）：它自身的两项授权，
        # documents:read 的来源只有 viewer，不混入 editor/reader。
        self.assert_mapping(
            ["viewer"],
            {
                PERMISSION_READ: ["viewer"],
                PERMISSION_PRIVATE: ["viewer"],
            },
            "单查 viewer",
        )

    # ---- 空结果 ----------------------------------------------------------

    def test_empty_roles_returns_empty_dict(self):
        # 空角色列表不查规则表，直接返回 {}；调用方列表也不应被改动。
        roles = []
        result = store.list_permission_roles_for_roles(self.conn, roles)
        self.assertEqual(
            result,
            {},
            f"空角色列表应返回 {{}}，实际为 {result!r}",
        )
        self.assertEqual(roles, [], "空角色列表调用后不应变化")

    def test_all_unauthorized_roles_return_empty_dict(self):
        # 样例中没有任何同名角色获授权限。
        self.assert_mapping(
            ["missing"],
            {},
            "单查从未获授权的 missing",
        )
        self.assert_mapping(
            ["missing", "nobody", "stranger"],
            {},
            "查询全部未获授权的角色",
        )
        self.assert_mapping(
            ["missing", "missing", "nobody"],
            {},
            "重复的未授权角色",
        )

    # ---- 精确匹配：大小写敏感、不裁剪空白 -------------------------------

    def test_reader_with_different_case_or_surrounding_whitespace_returns_empty(self):
        # 存储层不替调用方规整名称：Reader 与 reader 是不同角色；
        # 带首尾空白的名称也是不同角色。样例中这些角色均无授权，
        # 必须返回 {}，而不是命中 reader 的 documents:read。
        for roles in (
            ["Reader"],
            [" reader"],
            ["reader "],
            ["\treader\n"],
            [" reader "],
        ):
            with self.subTest(roles=roles):
                self.assert_mapping(
                    list(roles),
                    {},
                    f"查询角色名 {roles!r}",
                )

        # 对照：不带空白、大小写正确的 reader 正常命中，证明空结果
        # 确实来自精确匹配而非查询本身失效。
        self.assert_mapping(
            ["reader"],
            {PERMISSION_READ: ["reader"]},
            "对照：查询不带空白的 reader",
        )
        # 与 reader 混查时，变体名称不贡献来源，也不污染 reader 的结果。
        self.assert_mapping(
            ["Reader", " reader ", "reader"],
            {PERMISSION_READ: ["reader"]},
            "混查 [Reader, ' reader ', reader]",
        )

    # ---- 角色名中的 "*"、"%"、"_" 按普通字符精确匹配 --------------------

    def test_wildcard_chars_in_role_names_are_literal(self):
        # 直接把 "*"、"%"、"_" 以及含这些字符的名称作为普通角色名授权。
        literal_rules = (
            ("*", PERMISSION_READ),
            ("%", PERMISSION_READ),
            ("_", PERMISSION_READ),
            ("ed_tor", PERMISSION_WRITE),
        )
        for role, permission in literal_rules:
            self.assertTrue(
                store.grant_permission(self.conn, role, permission),
                f"测试前置：预置规则 {role}/{permission} 应实际新增",
            )

        # 只有完全相同的完整角色名才命中：
        # "*" 不匹配 editor 等其他角色，"_" 不模糊匹配 ed_tor，
        # 各来源恰为同名角色本身。
        self.assert_mapping(
            ["*"],
            {PERMISSION_READ: ["*"]},
            "查询角色 *",
        )
        self.assert_mapping(
            ["%"],
            {PERMISSION_READ: ["%"]},
            "查询角色 %",
        )
        self.assert_mapping(
            ["_"],
            {PERMISSION_READ: ["_"]},
            "查询角色 _",
        )
        self.assert_mapping(
            ["ed_tor"],
            {PERMISSION_WRITE: ["ed_tor"]},
            "查询含下划线的角色 ed_tor",
        )

        # 任何把这些字符当作通配符的“模糊匹配”都必须落空：
        # 不存在的同名角色返回 {}，且不会把 editor、ed_tor 的权限
        # 误带到这些名称下。
        for name in (
            "**",
            "%%",
            "__",
            "edit%r",
            "ed_tor_",
            "ed%tor",
            "edito?",
            "",  # 空串同样是一个不匹配任何角色的名称
        ):
            with self.subTest(name=name):
                self.assert_mapping(
                    [name],
                    {},
                    f"查询不应模糊命中的角色名 {name!r}",
                )

        # 把通配名称与普通角色一起查询时，来源各归其名，互不串扰。
        # documents:read 的来源按码点升序："%"(0x25) < "*"(0x2A) <
        # "_"(0x5F) < "editor"(e=0x65) < "reader"；
        # documents:write 的来源为 ed_tor 与 editor：比较到第 3 个字符，
        # '_'(0x5F) < 'i'(0x69)，故 ed_tor 在前。
        self.assert_mapping(
            ["reader", "_", "editor", "*", "%", "ed_tor"],
            {
                PERMISSION_READ: ["%", "*", "_", "editor", "reader"],
                PERMISSION_WRITE: ["ed_tor", "editor"],
            },
            "通配字符角色与普通角色混查",
        )

    # ---- 非 ASCII：名称原值保留，按 Unicode 码点升序 --------------------

    def test_non_ascii_names_preserved_and_sorted_by_unicode_codepoint(self):
        # 独立样例库：权限名与角色名都含非 ASCII，故意按与码点顺序不同的
        # 次序写入。角色：中、a、A 共享权限 读取；角色 中 另有 写入。
        unicode_db = os.path.join(self._tmpdir.name, "unicode_rules.db")
        conn = store.connect(unicode_db)
        self.addCleanup(conn.close)
        unicode_rules = (
            ("中", "读取"),
            ("a", "读取"),
            ("A", "读取"),
            ("中", "写入"),
        )
        for role, permission in unicode_rules:
            self.assertTrue(
                store.grant_permission(conn, role, permission),
                f"测试前置：预置规则 {role}/{permission} 应实际新增",
            )

        result = store.list_permission_roles_for_roles(
            conn, ["a", "中", "A", "a"]
        )
        # 权限键按完整名称 Unicode 码点升序：写入(0x5199) < 读取(0x8BFB)；
        # 来源角色按码点升序：A(0x41) < a(0x61) < 中(0x4E2D)。
        # 名称原值保留：大小写与中文字符均不转换。
        expected = {
            "写入": ["中"],
            "读取": ["A", "a", "中"],
        }
        self.assertEqual(
            result,
            expected,
            f"非 ASCII 名称应原值保留并按 Unicode 码点升序排列，"
            f"期望 {expected!r}，实际为 {result!r}",
        )
        self.assertEqual(
            list(result),
            ["写入", "读取"],
            f"权限键顺序应为码点升序，实际为 {list(result)!r}",
        )
        self.assertEqual(
            result["读取"],
            ["A", "a", "中"],
            f"来源角色顺序应为码点升序且原值保留，实际为 {result['读取']!r}",
        )

        # 同一连接重复调用结果一致，且全部授权记录（4 行）保持原样。
        self.assertEqual(
            store.list_permission_roles_for_roles(
                conn, ["a", "中", "A", "a"]
            ),
            result,
            "非 ASCII 样例重复查询结果应一致",
        )
        self.assertEqual(
            sorted(
                conn.execute(
                    "SELECT role, permission FROM role_permissions"
                ).fetchall()
            ),
            sorted(unicode_rules),
            "非 ASCII 样例查询后授权记录应保持原样",
        )

    # ---- 查询只读：重复调用与授权记录、表结构一致 -----------------------

    def test_repeated_calls_are_stable_and_read_only(self):
        rules_before = self.stored_rules()
        schema_before = self.conn.execute(
            "SELECT sql FROM sqlite_master WHERE name = 'role_permissions'"
        ).fetchone()[0]

        calls = (
            [],
            ["editor", "reader", "editor", "missing"],
            ["reader", "editor"],
            ["viewer"],
            ["missing", "nobody"],
            ["Reader", " reader "],
        )
        first_results = {}
        for roles in calls:
            with self.subTest(roles=roles):
                roles_copy = list(roles)
                result = store.list_permission_roles_for_roles(self.conn, roles)
                first_results[tuple(roles)] = result
                # 调用不修改入参列表。
                self.assertEqual(
                    roles,
                    roles_copy,
                    f"输入 {roles!r}：调用后角色列表被改动为 {roles!r}",
                )

        # 同一连接上以相同输入重复调用，返回相同结果。
        for roles in calls:
            with self.subTest(roles=roles):
                self.assertEqual(
                    store.list_permission_roles_for_roles(self.conn, roles),
                    first_results[tuple(roles)],
                    f"输入 {roles!r}：重复调用结果不一致，"
                    f"第一次 {first_results[tuple(roles)]!r}",
                )

        # 查询前后全部授权行一致。
        self.assertEqual(
            self.stored_rules(),
            rules_before,
            f"查询后授权记录发生变化，之前 {rules_before!r}，"
            f"之后 {self.stored_rules()!r}",
        )
        # 查询前后表结构一致。
        schema_after = self.conn.execute(
            "SELECT sql FROM sqlite_master WHERE name = 'role_permissions'"
        ).fetchone()[0]
        self.assertEqual(
            schema_after,
            schema_before,
            f"查询后表结构发生变化，之前 {schema_before!r}，之后 {schema_after!r}",
        )


class PermissionRolesForRolesIncompatibleSchemaTests(unittest.TestCase):
    """缺少 permission 列的现存规则表：存储失败不得退化为空映射。"""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.db_path = os.path.join(self._tmpdir.name, "rules.db")
        # 准备测试输入：表只有 role 列并保存一行 reader。
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
        rows = sorted(
            self.conn.execute("SELECT role FROM role_permissions").fetchall()
        )
        return schema, columns, rows

    def assert_state_unchanged(self, state_before, context):
        """调用后列定义与 reader 数据应与调用前一致：不补列、不改记录。"""
        state_after = self.stored_state()
        self.assertEqual(
            state_after,
            state_before,
            f"{context}：调用后表结构或数据发生变化，调用前为 {state_before!r}，"
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
            f"测试前置：表应只有 role 列并保存一行 reader，实际为 {state_before!r}",
        )

        # 非空角色列表必须查询 permission 列：缺列导致存储失败，
        # 必须抛出 rbac.store.StorageError，而非返回 {} 把失败伪装成
        # “这些角色均无授权”的正常空结果。
        with self.assertRaises(
            store.StorageError,
            msg="缺少 permission 列时非空角色列表查询应抛出 StorageError",
        ) as assertion_context:
            store.list_permission_roles_for_roles(self.conn, ["reader"])

        # 不得直接向外抛出 sqlite3 原始异常：StorageError 不是 sqlite3.Error，
        # 且其 __cause__ 中的底层 sqlite3 错误已被包装而非直通。
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
        # 无论角色名是否与预置行同名，只要查询触碰 permission 列就必然
        # 失败；重复角色与“看起来无授权”的角色同样失败，不得退化为 {}。
        for roles in (
            ["missing"],
            ["reader", "editor"],
            ["reader", "reader"],
            [" viewer "],
        ):
            with self.subTest(roles=roles):
                with self.assertRaises(store.StorageError):
                    store.list_permission_roles_for_roles(self.conn, roles)

    def test_empty_roles_on_incompatible_schema_returns_empty_dict(self):
        state_before = self.stored_state()

        # 空角色列表不触碰规则表：同一连接上仍返回 {}，缺列不影响此结果。
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
        # 两种路径都不得补列或改动预置数据，且空结果路径不被前一次
        # 失败污染；随后再次非空查询仍应失败。
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

        with self.assertRaises(store.StorageError):
            store.list_permission_roles_for_roles(self.conn, ["reader"])
        self.assert_state_unchanged(state_before, "再次存储失败后")


if __name__ == "__main__":
    unittest.main()
