"""rbac.policy.members_for_role 纯计算行为的单元测试。

只依赖 Python 3 标准库；不创建任何规则文件、不访问 SQLite，直接调用
rbac.policy.members_for_role 核对按角色反查固定关联成员的筛选、去重与
排序。从项目根目录执行：

    python -m unittest discover -s tests

覆盖范围：
- 用例内合成固定成员配置：alice 绑定 reader/editor/reader（含重复），
  bob 绑定 editor，Carol 绑定 reader，dave 绑定 writer，empty 无角色；
  members_for_role("reader") 恰为 ["Carol", "alice"]，
  members_for_role("editor") 恰为 ["alice", "bob"]，
  members_for_role("writer") 恰为 ["dave"]；
- 成员名按配置原值保留（含大小写），去重后按完整名称的 Unicode 码点
  升序排列；alice 的 reader 虽在配置中重复出现，结果中只出现一次；
- 无成员绑定的角色（ghost）、空字符串及任何未出现在配置中的名称均
  返回 []；无角色成员 empty 永远不进入结果；
- 本层按名称精确匹配，不做命令行名称规整："Reader"、" reader " 均不
  命中 reader；"*"、"%"、"_" 均为普通字符；
- 每次调用不修改输入与合成成员配置，重复调用返回相互独立的新列表；
- 每个用例结束后恢复原固定成员配置，即使断言失败也不影响后续用例。
"""

import copy
import unittest

from rbac import policy

# 用例内合成固定成员配置（alice 的 reader 重复出现，用于核对成员去重）。
SYNTHETIC_MEMBER_ROLES = {
    "alice": ("reader", "editor", "reader"),
    "bob": ("editor",),
    "Carol": ("reader",),
    "dave": ("writer",),
    "empty": (),
}


class MembersForRoleTests(unittest.TestCase):
    """在合成固定成员配置下直接核对 members_for_role 的纯计算行为。"""

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

    def assert_lookup(self, role, expected):
        """核对一次反查结果，并确认合成配置未被修改。"""
        config_snapshot = copy.deepcopy(policy.FIXED_MEMBER_ROLES)

        result = policy.members_for_role(role)

        self.assertEqual(
            result,
            expected,
            f"输入 {role!r}：期望 {expected!r}，实际为 {result!r}",
        )
        self.assertEqual(
            policy.FIXED_MEMBER_ROLES,
            config_snapshot,
            f"调用不应修改固定成员配置：调用前 {config_snapshot!r}，"
            f"调用后 {policy.FIXED_MEMBER_ROLES!r}",
        )
        return result

    # ---- 主流程 ---------------------------------------------------------

    def test_reader_returns_carol_and_alice_in_codepoint_order(self):
        # "Carol"(U+0043 起) < "alice"；成员名原样保留大小写。
        result = self.assert_lookup("reader", ["Carol", "alice"])

        members = list(result)
        self.assertEqual(
            members,
            sorted(members),
            f"成员应按码点升序排列，实际为 {members!r}",
        )
        # alice 的 reader 在合成配置中重复出现两次，成员只能出现一次。
        self.assertEqual(
            members.count("alice"),
            1,
            f"alice 不应因角色重复而重复出现，实际为 {members!r}",
        )
        self.assertEqual(members.count("Carol"), 1)

    def test_editor_returns_alice_and_bob(self):
        self.assert_lookup("editor", ["alice", "bob"])

    def test_writer_returns_dave(self):
        self.assert_lookup("writer", ["dave"])

    def test_unbound_or_unknown_roles_return_empty(self):
        # ghost 未被任何成员绑定；空字符串与含通配字符的名称同理。
        for role in ("ghost", "", "phantom", "reader2", " read*er "):
            with self.subTest(role=role):
                self.assert_lookup(role, [])

    def test_member_without_roles_never_appears(self):
        # empty 绑定空角色元组：任何角色查询都不应带出该成员。
        for role in ("reader", "editor", "writer", ""):
            with self.subTest(role=role):
                self.assertNotIn("empty", policy.members_for_role(role))

    # ---- 精确匹配口径 ---------------------------------------------------

    def test_match_is_case_sensitive_without_normalization(self):
        # 本层按名称精确匹配：不做大小写折叠、不去除首尾空白。
        for role in (
            "Reader",
            "READER",
            " reader",
            "reader ",
            "\treader\n",
            "Editor",
            "WRITER",
        ):
            with self.subTest(role=role):
                self.assert_lookup(role, [])

    def test_wildcard_chars_are_literal(self):
        # "*"、"%"、"_" 都是角色名的普通字符，不做通配匹配；
        # 合成配置中不存在含这些字符的角色，一律返回空列表。
        for role in ("reader*", "reader%", "reader_", "*", "%", "_", "read_er"):
            with self.subTest(role=role):
                self.assert_lookup(role, [])

        # 配置中确有含特殊字符的角色时，按完整名称精确命中。
        policy.FIXED_MEMBER_ROLES["zoe"] = ("read_er%",)
        self.assert_lookup("read_er%", ["zoe"])
        self.assert_lookup("read_er", [])
        self.assert_lookup("readXer%", [])

    def test_internal_whitespace_is_preserved(self):
        policy.FIXED_MEMBER_ROLES["zoe"] = ("re ader",)
        # 内部空白属于名称的一部分，不与 reader 混淆。
        self.assert_lookup("re ader", ["zoe"])
        self.assert_lookup("reader", ["Carol", "alice"])

    # ---- 结果稳定性 -----------------------------------------------------

    def test_repeated_calls_return_equal_fresh_results(self):
        first = self.assert_lookup("reader", ["Carol", "alice"])
        second = self.assert_lookup("reader", ["Carol", "alice"])
        self.assertEqual(first, second, "重复调用结果应一致")
        self.assertIsNot(first, second, "每次调用应返回独立的列表对象")

        # 修改首次返回结果不影响再次调用：结果不得共享内部状态。
        first.append("tampered")
        self.assert_lookup("reader", ["Carol", "alice"])


class DefaultMemberRolesRestoredTests(unittest.TestCase):
    """核对上述用例结束后默认固定成员配置保持原样。"""

    def test_default_config_is_alice_reader(self):
        self.assertEqual(
            policy.FIXED_MEMBER_ROLES,
            {"alice": ("reader",)},
            f"默认固定成员配置应只有 alice 绑定 reader，"
            f"实际为 {policy.FIXED_MEMBER_ROLES!r}",
        )
        self.assertEqual(policy.members_for_role("reader"), ["alice"])
        self.assertEqual(policy.members_for_role("editor"), [])


if __name__ == "__main__":
    unittest.main()
