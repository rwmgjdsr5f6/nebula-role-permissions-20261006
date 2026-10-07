"""rbac.policy.members_for_permission 纯计算行为的单元测试。

只依赖 Python 3 标准库；不创建任何规则文件、不访问 SQLite，直接调用
rbac.policy.members_for_permission 核对成员筛选与授权角色归因。从项目根目录
执行：

    python -m unittest discover -s tests

覆盖范围：
- 用例内合成固定成员配置：alice 绑定 reader/editor/reader（含重复），
  bob 绑定 editor，Carol 绑定 reader，dave 绑定 writer，empty 无角色；
  以 ["reader", "ghost", "editor", "reader"] 为直接获授角色输入时，完整
  结果为 [{"member": "Carol", "roles": ["reader"]},
           {"member": "alice", "roles": ["editor", "reader"]},
           {"member": "bob", "roles": ["editor"]}]；
- 每个命中成员只出现一次，roles 仅含该成员实际获授的直接角色并去重；
  无成员绑定的 ghost 不产生额外成员，未获授的 writer 与无角色的 empty
  不进入结果；
- 成员与各自 roles 分别按完整名称的 Unicode 码点升序排列，大小写原样
  保留；改变输入排列或增加重复角色不改变结果；
- 获授角色为空、只有未绑定角色，或只有 "Reader"、" reader " 等名称相近
  但不相等的角色时返回 []：本层按名称精确匹配，不做命令行名称规整；
- 每次调用前后输入角色列表与合成成员配置内容一致，重复调用结果一致；
- 每个用例结束后恢复原固定成员配置，即使断言失败也不影响后续用例。
"""

import copy
import unittest

from rbac import policy

# 用例内合成固定成员配置（alice 的 reader 重复出现，用于核对 roles 去重）。
SYNTHETIC_MEMBER_ROLES = {
    "alice": ("reader", "editor", "reader"),
    "bob": ("editor",),
    "Carol": ("reader",),
    "dave": ("writer",),
    "empty": (),
}

# 输入 ["reader", "ghost", "editor", "reader"] 的完整预期结果：
# 成员按码点升序（"Carol" < "alice" < "bob"），roles 同样按码点升序
# （"editor" < "reader"）；ghost 无成员绑定，writer 未获授，empty 无角色。
GRANTED_ROLES = ["reader", "ghost", "editor", "reader"]
EXPECTED_MEMBERS = [
    {"member": "Carol", "roles": ["reader"]},
    {"member": "alice", "roles": ["editor", "reader"]},
    {"member": "bob", "roles": ["editor"]},
]


class MembersForPermissionTests(unittest.TestCase):
    """在合成固定成员配置下直接核对 members_for_permission 的纯计算行为。"""

    def setUp(self):
        # 快照原配置并整体替换为合成配置；addCleanup 保证即使断言失败
        # 也会恢复原配置，不影响后续用例。
        self._original_member_roles = copy.deepcopy(policy.FIXED_MEMBER_ROLES)
        policy.FIXED_MEMBER_ROLES.clear()
        policy.FIXED_MEMBER_ROLES.update(
            copy.deepcopy(SYNTHETIC_MEMBER_ROLES)
        )
        self.addCleanup(self._restore_member_roles)

    def _restore_member_roles(self):
        policy.FIXED_MEMBER_ROLES.clear()
        policy.FIXED_MEMBER_ROLES.update(self._original_member_roles)

    # ---- 辅助方法 -------------------------------------------------------

    def assert_lookup(self, granted_roles, expected):
        """核对一次反查结果，并确认输入列表与合成配置未被修改。"""
        granted_snapshot = list(granted_roles)
        config_snapshot = copy.deepcopy(policy.FIXED_MEMBER_ROLES)

        result = policy.members_for_permission(granted_roles)

        self.assertEqual(
            result,
            expected,
            f"输入 {granted_roles!r}：期望 {expected!r}，实际为 {result!r}",
        )
        self.assertEqual(
            granted_roles,
            granted_snapshot,
            f"调用不应修改输入角色列表：调用前 {granted_snapshot!r}，"
            f"调用后 {granted_roles!r}",
        )
        self.assertEqual(
            policy.FIXED_MEMBER_ROLES,
            config_snapshot,
            f"调用不应修改固定成员配置：调用前 {config_snapshot!r}，"
            f"调用后 {policy.FIXED_MEMBER_ROLES!r}",
        )
        return result

    # ---- 主流程 ---------------------------------------------------------

    def test_full_expected_result(self):
        self.assert_lookup(list(GRANTED_ROLES), EXPECTED_MEMBERS)

    def test_result_shape_dedup_and_ordering(self):
        result = self.assert_lookup(list(GRANTED_ROLES), EXPECTED_MEMBERS)

        # 每个命中成员只出现一次。
        members = [item["member"] for item in result]
        self.assertEqual(
            len(members),
            len(set(members)),
            f"成员不应重复，实际为 {members!r}",
        )
        # 成员按完整名称的 Unicode 码点升序，大小写原样保留。
        self.assertEqual(
            members,
            sorted(members),
            f"成员应按码点升序排列，实际为 {members!r}",
        )
        self.assertIn("Carol", members, "大写开头的 Carol 应原样保留")
        # 每个成员的 roles 去重且按码点升序，仅含实际获授的直接角色。
        for item in result:
            self.assertEqual(
                item["roles"],
                sorted(set(item["roles"])),
                f"成员 {item['member']!r} 的角色应去重并按码点升序，"
                f"实际为 {item['roles']!r}",
            )
        # alice 的 roles 不含重复 reader；未获授的 writer 不出现。
        alice = next(item for item in result if item["member"] == "alice")
        self.assertEqual(alice["roles"], ["editor", "reader"])
        self.assertNotIn("dave", members, "writer 未获授，dave 不应进入结果")
        self.assertNotIn("empty", members, "无角色成员不应进入结果")

    def test_input_permutation_and_duplicates_do_not_change_result(self):
        variants = [
            ["reader", "editor"],
            ["editor", "reader"],
            ["reader", "ghost", "editor", "reader"],
            ["ghost", "editor", "ghost", "reader", "editor"],
            ["editor", "editor", "reader", "reader", "ghost"],
        ]
        for granted in variants:
            with self.subTest(granted=granted):
                self.assert_lookup(granted, EXPECTED_MEMBERS)

    def test_repeated_calls_return_equal_fresh_results(self):
        first = self.assert_lookup(list(GRANTED_ROLES), EXPECTED_MEMBERS)
        second = self.assert_lookup(list(GRANTED_ROLES), EXPECTED_MEMBERS)
        self.assertEqual(first, second, "重复调用结果应一致")
        self.assertIsNot(first, second, "每次调用应返回独立的结果对象")

        # 修改首次返回结果不影响再次调用：结果不得共享内部状态。
        first[0]["roles"].append("tampered")
        first.append({"member": "tampered", "roles": []})
        self.assert_lookup(list(GRANTED_ROLES), EXPECTED_MEMBERS)

    # ---- 边界用例 -------------------------------------------------------

    def test_empty_or_only_unbound_roles_return_empty(self):
        for granted in ([], ["ghost"], ["ghost", "phantom"], ["ghost", "ghost"]):
            with self.subTest(granted=granted):
                self.assert_lookup(granted, [])

    def test_exact_name_matching_without_normalization(self):
        # 本层按名称精确匹配：不做大小写规整、不去除首尾空白。
        for granted in (["Reader"], [" reader "], ["READER"], ["editor "], [" Editor"]):
            with self.subTest(granted=granted):
                self.assert_lookup(granted, [])

    def test_ungranted_roles_of_bound_members_still_match(self):
        # dave 绑定 writer：writer 获授时 dave 进入结果（对照主流程中
        # writer 未获授则不出现）。
        self.assert_lookup(
            ["writer"], [{"member": "dave", "roles": ["writer"]}]
        )
        # 无角色的 empty 在任何输入下都不进入结果。
        self.assert_lookup(
            ["reader", "writer"],
            [
                {"member": "Carol", "roles": ["reader"]},
                {"member": "alice", "roles": ["reader"]},
                {"member": "dave", "roles": ["writer"]},
            ],
        )


class DefaultMemberRolesRestoredTests(unittest.TestCase):
    """核对上述用例结束后默认固定成员配置保持原样。"""

    def test_default_config_is_alice_reader(self):
        self.assertEqual(
            policy.FIXED_MEMBER_ROLES,
            {"alice": ("reader",)},
            f"默认固定成员配置应只有 alice 绑定 reader，"
            f"实际为 {policy.FIXED_MEMBER_ROLES!r}",
        )
        self.assertEqual(
            policy.members_for_permission(["reader"]),
            [{"member": "alice", "roles": ["reader"]}],
        )
        self.assertEqual(policy.members_for_permission(["editor"]), [])


if __name__ == "__main__":
    unittest.main()
