"""rbac.policy.decide 纯计算行为的独立回归测试。

只依赖 Python 3 标准库；不创建数据库、不访问 SQLite、不新增命令，直接调用
rbac.policy.decide 核对决定字典。从项目根目录执行：

    python -m unittest discover -s tests -p test_policy_decide.py

覆盖范围：
- 用例内临时合成固定成员配置：alice 依次持有 reader、editor、reader（含
  重复），empty 角色为空元组，bob 不在配置中；
- alice + documents:read + 匹配 True 时完整决定为
  {"member": "alice", "permission": "documents:read",
   "roles": ["reader", "editor", "reader"],
   "allowed": True, "reason": "直接角色授权"}；
  仅把匹配值改为 False 时成员、权限与 roles 不变，allowed 为 False、
  reason 为“权限未授予”；roles 表示全部配置角色并保留顺序与重复项，
  不推断实际获授的是哪个角色；
- empty 与 bob 无论匹配值为 True 还是 False，都回显请求成员与权限，
  roles 为 []，allowed 为 False，reason 为“成员未配置”：无角色的
  拒绝原因优先于匹配值，匹配值只是规则匹配布尔量，不是授权操作；
- 重复调用内容相等，但结果对象与 roles 列表相互独立；修改第一次返回
  的 roles 后，下一次仍得到原配置角色，固定配置本身不变；
- 每个用例结束恢复原固定成员配置，断言失败时也完成恢复；全部用例
  结束后 alice 仍只绑定 reader。

名称均为有效字符串；名称校验（空白、大小写规整等）仍由命令行负责，
本层不重复测试。
"""

import copy
import unittest

from rbac import policy

# 用例内临时合成的固定成员配置：
# alice 的 reader 重复出现，用于核对 roles 保留顺序与重复项；
# empty 绑定空元组（已配置但无角色）；bob 不出现（未配置）。
SYNTHETIC_MEMBER_ROLES = {
    "alice": ("reader", "editor", "reader"),
    "empty": (),
}

MEMBER = "alice"
PERMISSION = "documents:read"
CONFIGURED_ROLES = ["reader", "editor", "reader"]

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


def expected_not_configured(member, permission):
    """无角色或未配置成员在任一匹配值下的完整预期决定。"""
    return {
        "member": member,
        "permission": permission,
        "roles": [],
        "allowed": False,
        "reason": "成员未配置",
    }


class DecideTests(unittest.TestCase):
    """在合成固定成员配置下直接核对 decide 的决定字典与原因优先级。"""

    def setUp(self):
        # 快照原配置并整体替换为合成配置；addCleanup 保证即使断言失败
        # 也会恢复原配置，不影响后续用例及其他测试模块。
        self._original_member_roles = copy.deepcopy(policy.FIXED_MEMBER_ROLES)
        policy.FIXED_MEMBER_ROLES.clear()
        policy.FIXED_MEMBER_ROLES.update(
            copy.deepcopy(SYNTHETIC_MEMBER_ROLES)
        )
        self.addCleanup(self._restore_member_roles)

    def _restore_member_roles(self):
        policy.FIXED_MEMBER_ROLES.clear()
        policy.FIXED_MEMBER_ROLES.update(self._original_member_roles)

    # ---- 允许与拒绝的完整决定 ------------------------------------------

    def test_allowed_full_result_when_matched(self):
        result = policy.decide(MEMBER, PERMISSION, True)
        self.assertEqual(
            result,
            EXPECTED_ALLOWED,
            f"匹配为 True 时应直接角色授权，实际为 {result!r}",
        )

    def test_not_granted_when_match_false(self):
        result = policy.decide(MEMBER, PERMISSION, False)
        self.assertEqual(
            result,
            EXPECTED_NOT_GRANTED,
            f"匹配为 False 时应权限未授予，实际为 {result!r}",
        )

    def test_only_allowed_and_reason_change_with_match_value(self):
        # 仅切换匹配值：成员、权限、roles 必须完全不变。
        allowed = policy.decide(MEMBER, PERMISSION, True)
        denied = policy.decide(MEMBER, PERMISSION, False)
        self.assertEqual(allowed["member"], denied["member"])
        self.assertEqual(allowed["permission"], denied["permission"])
        self.assertEqual(
            allowed["roles"],
            denied["roles"],
            "匹配值不应改变 roles：两种决定都应回显全部配置角色",
        )
        self.assertTrue(allowed["allowed"])
        self.assertFalse(denied["allowed"])
        self.assertEqual(allowed["reason"], "直接角色授权")
        self.assertEqual(denied["reason"], "权限未授予")

    def test_roles_are_all_configured_roles_with_order_and_duplicates(self):
        # roles 表示全部配置角色，保留顺序与重复项，不推断实际获授角色。
        for granted in (True, False):
            with self.subTest(granted=granted):
                result = policy.decide(MEMBER, PERMISSION, granted)
                self.assertEqual(
                    result["roles"],
                    CONFIGURED_ROLES,
                    f"roles 应保留全部配置角色（含顺序与重复项），"
                    f"实际为 {result['roles']!r}",
                )

    def test_match_boolean_is_not_an_authorization_action(self):
        # 传入匹配布尔量前后，固定配置内容保持不变；布尔量只参与判定。
        snapshot = copy.deepcopy(policy.FIXED_MEMBER_ROLES)
        policy.decide(MEMBER, PERMISSION, True)
        policy.decide(MEMBER, PERMISSION, False)
        self.assertEqual(
            policy.FIXED_MEMBER_ROLES,
            snapshot,
            "decide 不应因匹配值修改固定成员配置",
        )

    # ---- 原因优先级：无角色/未配置优先于匹配值 --------------------------

    def test_member_with_empty_roles_is_not_configured(self):
        # empty 已配置但角色为空：匹配值 True 也不能放行。
        for granted in (True, False):
            with self.subTest(granted=granted):
                result = policy.decide("empty", PERMISSION, granted)
                self.assertEqual(
                    result,
                    expected_not_configured("empty", PERMISSION),
                    f"empty + granted={granted}：实际为 {result!r}",
                )

    def test_unknown_member_is_not_configured(self):
        # bob 不在配置中：无论匹配值如何都按成员未配置拒绝。
        for granted in (True, False):
            with self.subTest(granted=granted):
                result = policy.decide("bob", PERMISSION, granted)
                self.assertEqual(
                    result,
                    expected_not_configured("bob", PERMISSION),
                    f"bob + granted={granted}：实际为 {result!r}",
                )

    def test_not_configured_reason_takes_priority_over_match(self):
        # 明确核对：即使规则匹配为 True，无角色仍优先拒绝。
        for member in ("empty", "bob"):
            with self.subTest(member=member):
                result = policy.decide(member, PERMISSION, True)
                self.assertFalse(result["allowed"])
                self.assertEqual(result["reason"], "成员未配置")
                self.assertEqual(result["roles"], [])

    def test_request_member_and_permission_are_echoed(self):
        # 拒绝决定同样原样回显请求的成员名与权限名。
        result = policy.decide("bob", "documents:write", False)
        self.assertEqual(result["member"], "bob")
        self.assertEqual(result["permission"], "documents:write")

    # ---- 重复调用的独立性 ------------------------------------------------

    def test_repeated_calls_equal_but_independent(self):
        first = policy.decide(MEMBER, PERMISSION, True)
        second = policy.decide(MEMBER, PERMISSION, True)
        self.assertEqual(first, second, "重复调用的决定内容应相等")
        self.assertIsNot(first, second, "每次调用应返回独立的决定对象")
        self.assertIsNot(
            first["roles"],
            second["roles"],
            "每次调用返回的 roles 列表应相互独立",
        )

    def test_mutating_first_roles_does_not_affect_next_call(self):
        config_snapshot = copy.deepcopy(policy.FIXED_MEMBER_ROLES)
        first = policy.decide(MEMBER, PERMISSION, True)
        first["roles"].append("tampered")
        first["allowed"] = False
        first["reason"] = "tampered"

        second = policy.decide(MEMBER, PERMISSION, True)
        self.assertEqual(
            second,
            EXPECTED_ALLOWED,
            f"修改首次返回值后再次调用应仍得原决定，实际为 {second!r}",
        )
        self.assertEqual(
            second["roles"],
            CONFIGURED_ROLES,
            "修改首次返回的 roles 后，下一次仍应得到原配置角色",
        )
        self.assertEqual(
            policy.FIXED_MEMBER_ROLES,
            config_snapshot,
            f"固定成员配置本身不应被调用或返回值修改影响，"
            f"实际为 {policy.FIXED_MEMBER_ROLES!r}",
        )

    def test_repeated_denials_also_independent(self):
        first = policy.decide("empty", PERMISSION, True)
        second = policy.decide("bob", PERMISSION, False)
        self.assertEqual(
            first,
            expected_not_configured("empty", PERMISSION),
        )
        self.assertEqual(
            second,
            expected_not_configured("bob", PERMISSION),
        )
        self.assertIsNot(first, second)
        self.assertIsNot(first["roles"], second["roles"])
        first["roles"].append("tampered")
        third = policy.decide("empty", PERMISSION, True)
        self.assertEqual(third["roles"], [])


class DefaultMemberRolesRestoredTests(unittest.TestCase):
    """核对上述用例结束后默认固定成员配置保持原样：alice 只绑定 reader。"""

    def test_default_config_is_alice_reader(self):
        self.assertEqual(
            policy.FIXED_MEMBER_ROLES,
            {"alice": ("reader",)},
            f"默认固定成员配置应只有 alice 绑定 reader，"
            f"实际为 {policy.FIXED_MEMBER_ROLES!r}",
        )

    def test_decide_under_restored_default_config(self):
        self.assertEqual(
            policy.decide("alice", PERMISSION, True),
            {
                "member": "alice",
                "permission": PERMISSION,
                "roles": ["reader"],
                "allowed": True,
                "reason": "直接角色授权",
            },
        )
        self.assertEqual(
            policy.decide("alice", PERMISSION, False),
            {
                "member": "alice",
                "permission": PERMISSION,
                "roles": ["reader"],
                "allowed": False,
                "reason": "权限未授予",
            },
        )
        self.assertEqual(
            policy.decide("bob", PERMISSION, True)["reason"],
            "成员未配置",
        )


if __name__ == "__main__":
    unittest.main()
