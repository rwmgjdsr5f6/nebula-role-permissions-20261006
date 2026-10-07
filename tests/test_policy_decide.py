"""rbac.policy.decide 纯计算行为的独立回归测试。

只依赖 Python 3 标准库；不创建数据库、不访问存储，直接以成员名、权限名和
规则匹配布尔值调用 rbac.policy.decide，核对返回的决定字典。从项目根目录
执行：

    python -m unittest discover -s tests -p test_policy_decide.py

覆盖范围：
- 用例内合成固定成员配置：alice 依次绑定 reader、editor、reader（保留顺序
  与重复项），empty 绑定空角色，bob 不在配置中；
- alice/documents:read 且匹配为 True 时允许，原因“直接角色授权”；匹配改为
  False 后仅 allowed/reason 变为 false/“权限未授予”，成员、权限与 roles 不变；
- roles 表示全部配置角色（含重复与顺序），不推断实际获授的是哪个角色；
- empty 与 bob 无论匹配值真假均拒绝，roles 为 []，原因“成员未配置”：
  无角色的拒绝原因优先于匹配值；
- 重复调用内容相等但结果对象与 roles 列表相互独立，修改前一次返回的 roles
  不影响后续调用，也不改变固定成员配置本身；
- 每个用例结束后恢复原固定成员配置，即使断言失败也完成恢复；全部用例结束
  后 alice 仍只绑定 reader。

名称校验（空名/纯空白/规整）仍由命令行入口负责，本层只接收有效字符串。
"""

import copy
import unittest

from rbac import policy

MEMBER = "alice"
PERMISSION = "documents:read"
CONFIGURED_ROLES = ["reader", "editor", "reader"]

# 用例内合成固定成员配置：alice 的 reader 重复出现，用于核对 roles 保留
# 顺序与重复项；empty 显式绑定空角色；bob 完全不在配置中。
SYNTHETIC_MEMBER_ROLES = {
    "alice": ("reader", "editor", "reader"),
    "empty": (),
}

EXPECTED_ALLOWED = {
    "member": "alice",
    "permission": "documents:read",
    "roles": ["reader", "editor", "reader"],
    "allowed": True,
    "reason": "直接角色授权",
}

EXPECTED_NOT_GRANTED = {
    "member": "alice",
    "permission": "documents:read",
    "roles": ["reader", "editor", "reader"],
    "allowed": False,
    "reason": "权限未授予",
}


class DecideTests(unittest.TestCase):
    """在合成固定成员配置下直接核对 decide 的决定字典。"""

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

    def assert_config_unchanged(self, snapshot):
        self.assertEqual(
            policy.FIXED_MEMBER_ROLES,
            snapshot,
            f"decide 不应修改固定成员配置：调用前 {snapshot!r}，"
            f"调用后 {policy.FIXED_MEMBER_ROLES!r}",
        )

    # ---- 允许 / 权限未授予 ---------------------------------------------

    def test_allowed_when_rule_matches(self):
        snapshot = copy.deepcopy(policy.FIXED_MEMBER_ROLES)
        result = policy.decide(MEMBER, PERMISSION, True)
        self.assertEqual(
            result,
            EXPECTED_ALLOWED,
            f"匹配为 True 时的决定与预期不符，实际为 {result!r}",
        )
        # 决定字典只包含固定的五个键。
        self.assertEqual(
            set(result.keys()),
            {"member", "permission", "roles", "allowed", "reason"},
            f"决定字典的键集合与预期不符，实际为 {set(result.keys())!r}",
        )
        # 匹配值只是入参，decide 不执行任何授权操作、不改配置。
        self.assert_config_unchanged(snapshot)

    def test_not_granted_when_rule_does_not_match(self):
        snapshot = copy.deepcopy(policy.FIXED_MEMBER_ROLES)
        result = policy.decide(MEMBER, PERMISSION, False)
        self.assertEqual(
            result,
            EXPECTED_NOT_GRANTED,
            f"匹配为 False 时的决定与预期不符，实际为 {result!r}",
        )
        self.assert_config_unchanged(snapshot)

    def test_only_allowed_and_reason_change_with_match_value(self):
        allowed = policy.decide(MEMBER, PERMISSION, True)
        denied = policy.decide(MEMBER, PERMISSION, False)

        # 成员、权限、roles 不随匹配值变化；仅 allowed 与 reason 不同。
        for key in ("member", "permission", "roles"):
            self.assertEqual(
                allowed[key],
                denied[key],
                f"匹配值变化不应改变 {key}：{allowed[key]!r} vs {denied[key]!r}",
            )
        self.assertTrue(allowed["allowed"])
        self.assertFalse(denied["allowed"])
        self.assertEqual(allowed["reason"], "直接角色授权")
        self.assertEqual(denied["reason"], "权限未授予")

    def test_roles_include_all_configured_roles_in_order_with_duplicates(self):
        # roles 表示全部配置角色，保留顺序与重复项，不推断实际获授的是
        # 哪个角色：无论匹配真假，三个角色都原样出现。
        for granted in (True, False):
            with self.subTest(granted=granted):
                result = policy.decide(MEMBER, PERMISSION, granted)
                self.assertEqual(
                    result["roles"],
                    CONFIGURED_ROLES,
                    f"granted={granted}：roles 应为全部配置角色（含顺序与"
                    f"重复项），实际为 {result['roles']!r}",
                )

        # 与配置中的角色序列内容一致，但不是同一个对象。
        configured = policy.FIXED_MEMBER_ROLES["alice"]
        result = policy.decide(MEMBER, PERMISSION, True)
        self.assertEqual(result["roles"], list(configured))
        self.assertIsNot(
            result["roles"],
            configured,
            "返回的 roles 应是新建列表，不应与配置共享对象",
        )

    # ---- 成员未配置：原因优先级 ----------------------------------------

    def test_member_without_roles_denied_regardless_of_match(self):
        # empty 显式绑定空角色，bob 不在配置中：匹配值 True/False 都拒绝，
        # 无角色的拒绝原因优先于匹配值（即使 True 也不允许）。
        for member in ("empty", "bob"):
            for granted in (True, False):
                with self.subTest(member=member, granted=granted):
                    result = policy.decide(member, PERMISSION, granted)
                    self.assertEqual(
                        result,
                        {
                            "member": member,
                            "permission": PERMISSION,
                            "roles": [],
                            "allowed": False,
                            "reason": "成员未配置",
                        },
                        f"成员 {member!r}、granted={granted} 的决定与预期不符，"
                        f"实际为 {result!r}",
                    )

    def test_no_role_reason_takes_precedence_over_match(self):
        # 直接断言：对无角色成员传入 True，原因仍是“成员未配置”而非允许。
        result = policy.decide("bob", PERMISSION, True)
        self.assertFalse(result["allowed"])
        self.assertEqual(result["reason"], "成员未配置")
        self.assertEqual(result["roles"], [])

    def test_requested_names_are_echoed_verbatim(self):
        # 成员名与权限名按输入原样返回，本层不做规整。
        result = policy.decide("bob", "documents:write", False)
        self.assertEqual(result["member"], "bob")
        self.assertEqual(result["permission"], "documents:write")

    # ---- 重复调用的独立性 ----------------------------------------------

    def test_repeated_calls_are_equal_but_independent(self):
        first = policy.decide(MEMBER, PERMISSION, True)
        second = policy.decide(MEMBER, PERMISSION, True)

        self.assertEqual(first, second, "重复调用的决定内容应相等")
        self.assertIsNot(first, second, "每次调用应返回独立的结果对象")
        self.assertIsNot(
            first["roles"],
            second["roles"],
            "每次调用返回的 roles 列表应相互独立",
        )

    def test_mutating_returned_roles_does_not_affect_later_calls_or_config(self):
        snapshot = copy.deepcopy(policy.FIXED_MEMBER_ROLES)
        first = policy.decide(MEMBER, PERMISSION, True)

        # 修改第一次返回的 roles 列表。
        first["roles"].append("administrator")
        first["roles"].reverse()

        # 下一次调用仍得到原配置角色，配置本身也不变。
        second = policy.decide(MEMBER, PERMISSION, True)
        self.assertEqual(
            second["roles"],
            CONFIGURED_ROLES,
            f"修改前一次返回的 roles 后，再次调用应仍得到原配置角色，"
            f"实际为 {second['roles']!r}",
        )
        self.assertEqual(
            second,
            EXPECTED_ALLOWED,
            f"修改前一次结果不应影响后续决定，实际为 {second!r}",
        )
        self.assert_config_unchanged(snapshot)

        # 无角色成员返回的空列表同样是独立对象。
        empty_first = policy.decide("empty", PERMISSION, False)
        empty_second = policy.decide("empty", PERMISSION, False)
        self.assertIsNot(empty_first["roles"], empty_second["roles"])
        bob_first = policy.decide("bob", PERMISSION, False)
        self.assertIsNot(bob_first["roles"], empty_first["roles"])


class DefaultMemberRolesRestoredTests(unittest.TestCase):
    """核对上述用例结束后默认固定成员配置保持原样。"""

    def test_default_config_is_alice_reader(self):
        self.assertEqual(
            policy.FIXED_MEMBER_ROLES,
            {"alice": ("reader",)},
            f"默认固定成员配置应只有 alice 绑定 reader，"
            f"实际为 {policy.FIXED_MEMBER_ROLES!r}",
        )

    def test_decide_uses_restored_default_config(self):
        allowed = policy.decide("alice", PERMISSION, True)
        self.assertEqual(
            allowed,
            {
                "member": "alice",
                "permission": PERMISSION,
                "roles": ["reader"],
                "allowed": True,
                "reason": "直接角色授权",
            },
        )
        denied = policy.decide("alice", PERMISSION, False)
        self.assertEqual(denied["allowed"], False)
        self.assertEqual(denied["reason"], "权限未授予")
        # 合成配置中的 empty 已随恢复消失，重新按未配置成员处理。
        unknown = policy.decide("empty", PERMISSION, True)
        self.assertEqual(
            unknown,
            {
                "member": "empty",
                "permission": PERMISSION,
                "roles": [],
                "allowed": False,
                "reason": "成员未配置",
            },
        )


if __name__ == "__main__":
    unittest.main()
