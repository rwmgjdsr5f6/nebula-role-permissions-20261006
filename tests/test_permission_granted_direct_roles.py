"""rbac.store.permission_granted 直接角色匹配的回归测试。

本文件只覆盖既有语义，不新增任何权限规则功能：permission_granted 接收
一个数据库连接、一个角色列表和一个权限名，当列表中任一直接角色在规则库
中拥有该权限时返回 True，否则返回 False。固定成员关系（alice -> reader）
属于 rbac.policy 的合成数据，不入库；这些用例不改动它，也不经过命令行。

规则库固定样例（真实 SQLite 数据，经 rbac.store 的标准建表与授予写入）：

    reader -> documents:read
    editor -> documents:write
    ghost  -> documents:read

覆盖范围：
- 任一角色命中语义：["reader","editor"] 查询 documents:write 为 True
  （即使只有第二个角色获授）；交换角色顺序、重复 editor 后仍为 True；
- 不串角色、不串权限：只给 reader 查 write、只给 editor 查 read、
  ghost 的 read 不带来 write、从未获授任何权限的角色，均为 False；
- 空角色列表为 False（不触碰规则表）；
- 大小写敏感：Reader 不等同 reader，Documents:read 不等同 documents:read；
- 百分号是普通字符而非通配符：reader 查询 documents:% 不匹配已有的
  documents:read，为 False；为 reader 保存 documents:% 后同查询才为 True；
- 只读与稳定：每次调用前后角色输入本身和完整授权记录一致，重复调用
  结果稳定；
- 存储失败与正常拒绝明确区分：规则表只有 role 列、缺少 permission 列时，
  非空角色列表必须抛 rbac.store.StorageError，不能返回 False；同一连接
  上空角色列表仍返回 False，不补列、不改动已有数据。

只依赖 Python 3 标准库与 SQLite；每个用例使用独立临时目录中的本地测试库，
连接在 tearDown 中关闭，结束后自动清理，不依赖网络或外部包。
从项目根目录执行：

    python -m unittest discover -s tests
"""

import os
import sqlite3
import sys
import tempfile
import unittest

# tests/ 的上一级即项目根目录（rbac 包所在目录）；直接导入被测存储模块。
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from rbac import store  # noqa: E402

PERMISSION_READ = "documents:read"
PERMISSION_WRITE = "documents:write"
PERMISSION_PERCENT = "documents:%"

# 固定样例中预置的全部直接角色授权。
SEED_RULES = [
    ("reader", PERMISSION_READ),
    ("editor", PERMISSION_WRITE),
    ("ghost", PERMISSION_READ),
]

# 不兼容的表结构：只有 role 列，缺少 permission 列。
_INCOMPATIBLE_SCHEMA = "CREATE TABLE role_permissions (role TEXT)"


class PermissionGrantedDirectRolesTests(unittest.TestCase):
    """直接传入角色列表与权限名，用真实 SQLite 规则数据核对布尔结果。"""

    def setUp(self):
        # 每个用例独立的临时目录，TemporaryDirectory.cleanup 负责清理。
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.tmpdir = self._tmpdir.name
        self.db_path = os.path.join(self.tmpdir, "rules.db")

        # 经被测模块自身的建表与授予接口写入固定样例，保证测试面对的是
        # 与生产一致的真实规则数据。
        self.conn = store.connect(self.db_path)
        self.addCleanup(self.conn.close)
        for role, permission in SEED_RULES:
            self.assertTrue(
                store.grant_permission(self.conn, role, permission),
                f"测试前置：预置 {role}/{permission} 应为实际新增",
            )

    # ---- 辅助方法 -------------------------------------------------------

    def all_rules(self):
        """直接读取 SQLite，返回排序后的完整 (role, permission) 授权记录。"""
        return sorted(
            self.conn.execute(
                "SELECT role, permission FROM role_permissions"
            ).fetchall()
        )

    def assert_rules_unchanged(self, rules_before, context):
        """调用前后完整授权记录必须一致（permission_granted 为只读查询）。"""
        self.assertEqual(
            self.all_rules(),
            rules_before,
            f"{context}：调用前后授权记录应一致，调用前 {rules_before!r}，"
            f"调用后 {self.all_rules()!r}",
        )

    def assert_granted_stable(self, roles, permission, expected, context):
        """核对布尔结果、角色输入不变、授权记录不变、重复调用稳定。"""
        roles_before = list(roles)
        rules_before = self.all_rules()

        result = store.permission_granted(self.conn, list(roles), permission)
        self.assertIs(
            result,
            expected,
            f"{context}：roles={list(roles)!r} 查询 {permission!r} 应为 {expected!r}，"
            f"实际为 {result!r}",
        )

        # 传入的角色列表内容不得被查询改写。
        self.assertEqual(
            list(roles),
            roles_before,
            f"{context}：角色输入在调用后发生变化，之前 {roles_before!r}，"
            f"之后 {list(roles)!r}",
        )
        self.assert_rules_unchanged(rules_before, context)

        # 重复调用结果稳定。
        repeated = store.permission_granted(self.conn, list(roles), permission)
        self.assertIs(
            repeated,
            expected,
            f"{context}：重复调用结果应稳定为 {expected!r}，实际为 {repeated!r}",
        )
        self.assert_rules_unchanged(rules_before, context)

    # ---- 任一角色命中 ---------------------------------------------------

    def test_any_matching_role_allows_even_when_only_second_role_granted(self):
        # reader 没有 write、editor 有 write：任一角色命中即允许。
        self.assert_granted_stable(
            ["reader", "editor"],
            PERMISSION_WRITE,
            True,
            "两个角色中仅第二个获授 documents:write",
        )

    def test_role_order_does_not_affect_result(self):
        # 交换顺序后仍应允许。
        self.assert_granted_stable(
            ["editor", "reader"],
            PERMISSION_WRITE,
            True,
            "交换角色顺序",
        )

    def test_duplicate_granted_role_still_allows(self):
        # 重复出现的 editor 不改变命中语义。
        self.assert_granted_stable(
            ["editor", "editor", "reader"],
            PERMISSION_WRITE,
            True,
            "重复获授角色 editor",
        )
        self.assert_granted_stable(
            ["reader", "editor", "editor"],
            PERMISSION_WRITE,
            True,
            "末尾重复获授角色 editor",
        )

    def test_direct_match_allows_for_each_seeded_permission(self):
        # 固定样例中的每条授权本身都应命中。
        self.assert_granted_stable(
            ["reader"], PERMISSION_READ, True, "reader 查 documents:read"
        )
        self.assert_granted_stable(
            ["editor"], PERMISSION_WRITE, True, "editor 查 documents:write"
        )
        self.assert_granted_stable(
            ["ghost"], PERMISSION_READ, True, "ghost 查 documents:read"
        )

    # ---- 不串角色、不串权限 ---------------------------------------------

    def test_reader_is_not_granted_editor_permission(self):
        self.assert_granted_stable(
            ["reader"],
            PERMISSION_WRITE,
            False,
            "只查询 reader 的 documents:write",
        )

    def test_editor_is_not_granted_reader_permission(self):
        self.assert_granted_stable(
            ["editor"],
            PERMISSION_READ,
            False,
            "只查询 editor 的 documents:read",
        )

    def test_ghost_read_does_not_extend_to_other_permission(self):
        # ghost 持有 read 不代表持有 write；授权不得跨权限串用。
        self.assert_granted_stable(
            ["ghost"],
            PERMISSION_WRITE,
            False,
            "ghost 查 documents:write",
        )

    def test_ungranted_role_is_denied_for_known_permissions(self):
        # 从未获授任何权限的角色，对已存在的权限也一律拒绝。
        for roles, permission in (
            (["stranger"], PERMISSION_READ),
            (["stranger"], PERMISSION_WRITE),
            (["stranger", "nobody"], PERMISSION_READ),
        ):
            self.assert_granted_stable(
                roles,
                permission,
                False,
                f"从未获授的角色 {roles!r} 查 {permission!r}",
            )

    def test_other_role_in_list_cannot_leak_its_grant(self):
        # 列表中混入获授角色时只在“同一权限”上放行；
        # editor 的 write 不能让 reader 的 read 查询越权。
        self.assert_granted_stable(
            ["reader", "ghost"],
            PERMISSION_WRITE,
            False,
            "两个仅有 read 的角色查 write",
        )
        self.assert_granted_stable(
            ["editor", "stranger"],
            PERMISSION_READ,
            False,
            "仅有 write 的 editor 搭配未知角色查 read",
        )

    # ---- 空角色列表 -----------------------------------------------------

    def test_empty_role_list_is_denied(self):
        for permission in (PERMISSION_READ, PERMISSION_WRITE, PERMISSION_PERCENT):
            self.assert_granted_stable(
                [],
                permission,
                False,
                f"空角色列表查 {permission!r}",
            )

        # 元组形态的空角色序列同样为 False。
        self.assertIs(
            store.permission_granted(self.conn, (), PERMISSION_READ),
            False,
            "空角色元组查询应返回 False",
        )

    # ---- 大小写敏感的完整字符串匹配 --------------------------------------

    def test_role_and_permission_matching_is_case_sensitive(self):
        # 角色 Reader 不等同于 reader。
        self.assert_granted_stable(
            ["Reader"],
            PERMISSION_READ,
            False,
            "大写开头的角色 Reader",
        )
        # 权限 Documents:read 不等同于 documents:read。
        self.assert_granted_stable(
            ["reader"],
            "Documents:read",
            False,
            "大写开头的权限 Documents:read",
        )
        # 两者同时写错大小写，也不得互相凑成命中。
        self.assert_granted_stable(
            ["Reader"],
            "Documents:read",
            False,
            "角色与权限均为不同大小写",
        )
        # 大小写不同的名称不得“占用”既有授权：原样的 reader/read 仍允许。
        self.assert_granted_stable(
            ["reader"],
            PERMISSION_READ,
            True,
            "大小写核对后原样 reader/documents:read 仍允许",
        )

    # ---- 百分号按普通字符精确匹配 ----------------------------------------

    def test_percent_sign_is_a_literal_and_must_be_granted_explicitly(self):
        # documents:% 不得当作通配符匹配已有的 documents:read。
        self.assert_granted_stable(
            ["reader"],
            PERMISSION_PERCENT,
            False,
            "未授予 documents:% 时按字面精确匹配",
        )
        self.assert_granted_stable(
            ["editor", "ghost"],
            PERMISSION_PERCENT,
            False,
            "其他角色同样不因字面百分号获得放行",
        )

        rules_before = self.all_rules()
        # 显式为 reader 保存 documents:%（百分号作为普通字符入库）。
        self.assertTrue(
            store.grant_permission(self.conn, "reader", PERMISSION_PERCENT),
            "为 reader 保存字面权限 documents:% 应实际新增",
        )

        # 保存之后，相同查询才返回 True。
        self.assertIs(
            store.permission_granted(self.conn, ["reader"], PERMISSION_PERCENT),
            True,
            "显式授予 documents:% 后同查询应为 True",
        )
        # 新规则不影响既有的 documents:read 判定，也不产生通配效果。
        self.assertIs(
            store.permission_granted(self.conn, ["reader"], PERMISSION_READ),
            True,
            "授予 documents:% 后 documents:read 仍按各自规则允许",
        )
        self.assertIs(
            store.permission_granted(self.conn, ["ghost"], PERMISSION_PERCENT),
            False,
            "documents:% 只授予 reader，ghost 不得借用",
        )
        self.assertIs(
            store.permission_granted(self.conn, ["reader"], "documents:%%"),
            False,
            "documents:%% 是另一个字面权限名，不得命中 documents:%",
        )

        # 授权记录恰好多出且只多出这一条精确规则。
        self.assertEqual(
            self.all_rules(),
            sorted(rules_before + [("reader", PERMISSION_PERCENT)]),
            f"保存 documents:% 后授权记录应只新增该字面规则，"
            f"实际为 {self.all_rules()!r}",
        )

    # ---- 多次查询互不影响、固定样例始终完整 ------------------------------

    def test_mixed_query_sequence_keeps_results_and_seed_data_stable(self):
        rules_before = self.all_rules()
        self.assertEqual(
            rules_before,
            sorted(SEED_RULES),
            f"测试前置：固定样例授权应完整，实际为 {rules_before!r}",
        )

        sequence = [
            (["reader", "editor"], PERMISSION_WRITE, True),
            (["editor", "reader"], PERMISSION_WRITE, True),
            (["reader"], PERMISSION_WRITE, False),
            (["editor"], PERMISSION_READ, False),
            (["ghost"], PERMISSION_WRITE, False),
            (["stranger"], PERMISSION_READ, False),
            ([], PERMISSION_READ, False),
            (["Reader"], PERMISSION_READ, False),
            (["reader"], "Documents:read", False),
            (["reader"], PERMISSION_PERCENT, False),
        ]
        # 连续跑两遍：任意顺序的查询之间互不影响，结果稳定。
        for repetition in (1, 2):
            for roles, permission, expected in sequence:
                with self.subTest(
                    repetition=repetition, roles=roles, permission=permission
                ):
                    self.assertIs(
                        store.permission_granted(
                            self.conn, list(roles), permission
                        ),
                        expected,
                        f"第 {repetition} 轮：roles={roles!r} 查 {permission!r}"
                        f"应为 {expected!r}",
                    )

        self.assert_rules_unchanged(rules_before, "整串混合查询")


class PermissionGrantedIncompatibleSchemaTests(unittest.TestCase):
    """缺 permission 列的现存规则表：存储失败必须区别于正常拒绝。"""

    def setUp(self):
        # 每个用例独立的临时目录与独立的本地测试库。
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.tmpdir = self._tmpdir.name
        self.db_path = os.path.join(self.tmpdir, "rules.db")
        # 准备现存表：只有 role 列并保存一行 reader。
        with sqlite3.connect(self.db_path) as setup_conn:
            setup_conn.execute(_INCOMPATIBLE_SCHEMA)
            setup_conn.execute(
                "INSERT INTO role_permissions (role) VALUES ('reader')"
            )
            setup_conn.commit()

        # store.connect 的 CREATE TABLE IF NOT EXISTS 对已有表为空操作，
        # 不会补列；与命令行入口打开同一缺列库的路径一致。
        self.conn = store.connect(self.db_path)
        self.addCleanup(self.conn.close)

    def stored_state(self):
        """直接读取 SQLite，返回 (建表语句, 列定义, 按 role 排序的全部行)。"""
        with sqlite3.connect(self.db_path) as probe:
            schema = probe.execute(
                "SELECT sql FROM sqlite_master WHERE name = 'role_permissions'"
            ).fetchone()[0]
            columns = probe.execute(
                "PRAGMA table_info(role_permissions)"
            ).fetchall()
            rows = sorted(
                probe.execute("SELECT role FROM role_permissions").fetchall()
            )
        return schema, columns, rows

    def test_nonempty_roles_raise_storage_error_instead_of_false(self):
        state_before = self.stored_state()
        self.assertEqual(
            state_before,
            (_INCOMPATIBLE_SCHEMA, [(0, "role", "TEXT", 0, None, 0)], [("reader",)]),
            f"测试前置：表应只有 role 列并保存一行 reader，实际为 {state_before!r}",
        )

        # 缺列导致查询无法执行：这是存储失败，绝不能以 False 的正常拒绝形式返回。
        for roles, permission in (
            (["reader"], PERMISSION_READ),
            (["reader", "editor"], PERMISSION_WRITE),
            (["ghost"], PERMISSION_READ),
        ):
            with self.subTest(roles=roles, permission=permission):
                with self.assertRaises(store.StorageError):
                    store.permission_granted(
                        self.conn, list(roles), permission
                    )

        # 失败后不补列、不改动已有数据。
        self.assertEqual(
            self.stored_state(),
            state_before,
            f"存储失败后表结构与数据应保持不变，调用前 {state_before!r}，"
            f"调用后 {self.stored_state()!r}",
        )
        column_names = [column[1] for column in self.stored_state()[1]]
        self.assertEqual(
            column_names,
            ["role"],
            f"失败后不得补出 permission 列，实际列为 {column_names!r}",
        )

    def test_empty_roles_still_return_false_on_same_connection(self):
        # 同一缺列连接上：空角色列表在查询前直接返回 False，不触碰规则表，
        # 因而既不抛 StorageError，也不补列、不改数据。
        state_before = self.stored_state()

        for permission in (PERMISSION_READ, PERMISSION_WRITE):
            with self.subTest(permission=permission):
                self.assertIs(
                    store.permission_granted(self.conn, [], permission),
                    False,
                    f"空角色列表查 {permission!r} 应正常返回 False",
                )

        self.assertEqual(
            self.stored_state(),
            state_before,
            f"空角色列表查询后表结构与数据应保持不变，调用前 {state_before!r}，"
            f"调用后 {self.stored_state()!r}",
        )

    def test_storage_error_and_normal_denial_are_distinguished(self):
        # 同一连接连续调用：非空角色抛 StorageError，空角色返回 False；
        # 两者必须可明确区分，且互不影响。空角色调用不“修复”缺列。
        state_before = self.stored_state()

        self.assertIs(
            store.permission_granted(self.conn, [], PERMISSION_READ),
            False,
            "先查空角色列表：正常拒绝 False",
        )
        with self.assertRaises(store.StorageError):
            store.permission_granted(self.conn, ["reader"], PERMISSION_READ)
        self.assertIs(
            store.permission_granted(self.conn, [], PERMISSION_READ),
            False,
            "存储失败后再查空角色列表：仍为正常拒绝 False",
        )
        with self.assertRaises(store.StorageError):
            store.permission_granted(
                self.conn, ["reader", "editor"], PERMISSION_WRITE
            )

        self.assertEqual(
            self.stored_state(),
            state_before,
            "区分存储失败与正常拒绝的整串调用后，表结构与数据应保持不变",
        )


if __name__ == "__main__":
    unittest.main()
