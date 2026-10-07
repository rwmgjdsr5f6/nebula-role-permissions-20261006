"""rbac.policy.members_for_permission 纯计算行为的独立单元测试。

不经过命令行子进程，直接在用例内替换固定成员配置（合成配置），核对
按直接获授角色反查获准成员的纯内存计算：

- 合成配置：alice 绑定 reader、editor、reader（含重复），bob 绑定
  editor，Carol 绑定 reader，dave 绑定 writer，empty 不绑定任何角色；
- 直接获授角色 ["reader", "ghost", "editor", "reader"] 的完整预期结果为
  [{"member": "Carol", "roles": ["reader"]},
   {"member": "alice", "roles": ["editor", "reader"]},
   {"member": "bob", "roles": ["editor"]}]：
  每个命中成员只出现一次，roles 仅含该成员实际获授的直接角色并去重；
  无成员绑定的 ghost 不产生额外成员，未获授的 writer（dave）与无角色
  成员（empty）不进入结果；成员与各自 roles 分别按完整名称的 Unicode
  码点升序排列（"Carol" 在 "alice" 之前），大小写原样保留；
- 改变输入排列或增加重复角色不改变结果；
- 获授角色为空、只有未绑定角色，或仅大小写/首尾空白不同（"Reader"、
  " reader "）时返回 []——这一层按名称精确匹配，不做命令行的名称规整；
- 每次调用前后输入角色列表与合成成员配置内容保持一致，重复调用结果
  一致；纯内存计算，不创建任何规则文件；
- 每个用例结束后恢复 policy.FIXED_MEMBER_ROLES 原配置（默认 alice
  对应 reader），即使断言失败也不影响后续用例。

只依赖 Python 3 标准库。从项目根目录执行：

    python -m unittest discover -s tests
"""

import copy
import os
import sys
import tempfile
import unittest
from unittest import mock

# tests/ 的上一级即项目根目录（rbac 包所在目录）；保证任意当前工作
# 目录下都能导入 rbac 包。
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from rbac import policy

# 用例内限定的合成成员配置：成员 -> 直接角色元组。
SYNTHETIC_MEMBER_ROLES = {
    "alice": ("reader", "editor", "reader"),
    "bob": ("editor",),
    "Carol": ("reader",),
    "dave": ("writer",),
    "empty": (),
}

# 同一权限的直接获授角色输入：含未绑定成员的角色 ghost 与重复项。
GRANTED_ROLES = ["reader", "ghost", "editor", "reader"]

# 完整预期结果：成员与 roles 均按完整名称的 Unicode 码点升序。
EXPECTED_MEMBERS = [
    {"member": "Carol", "roles": ["reader"]},
    {"member": "alice", "roles": ["editor", "reader"]},
    {"member": "bob", "roles": ["editor"]},
]


class MembersForPermissionTests(unittest.TestCase):
    """在合成成员配置下核对 members_for_permission 的纯计算行为。"""

    def setUp(self):
        # 深拷贝保存原配置与合成配置，供用例后比对与恢复。
        self._original_config = copy.deepcopy(policy.FIXED_MEMBER_ROLES)
        self._synthetic_snapshot = copy.deepcopy(SYNTHETIC_MEMBER_ROLES)
        # 用例内限定：以合成配置整体替换固定成员配置；clear=True 先清空
        # 再写入，stop 时恢复原内容，即使断言失败也会执行恢复。
        patcher = mock.patch.dict(
            policy.FIXED_MEMBER_ROLES, SYNTHETIC_MEMBER_ROLES, clear=True
        )
        # addCleanup 按后进先出执行：先登记恢复核对，后登记 stop，
        # 保证 stop 先执行、核对在恢复之后进行。
        self.addCleanup(self.assert_config_restored)
        patcher.start()
        self.addCleanup(patcher.stop)

    # ---- 辅助方法 -------------------------------------------------------

    def assert_config_restored(self):
        """用例结束后：固定成员配置已恢复为进入用例前的内容。"""
        self.assertEqual(
            policy.FIXED_MEMBER_ROLES,
            self._original_config,
            f"用例结束后固定成员配置应恢复原样，期望 {self._original_config!r}，"
            f"实际为 {policy.FIXED_MEMBER_ROLES!r}",
        )

    def assert_config_is_synthetic(self):
        """用例进行中：当前生效的确为合成配置且内容未被调用改变。"""
        self.assertEqual(
            policy.FIXED_MEMBER_ROLES,
            self._synthetic_snapshot,
            f"合成成员配置在调用前后应保持一致，期望 {self._synthetic_snapshot!r}，"
            f"实际为 {policy.FIXED_MEMBER_ROLES!r}",
        )

    def lookup(self, granted_roles):
        """执行一次反查，并核对输入列表与合成配置未被调用改变。"""
        granted_before = list(granted_roles)
        self.assert_config_is_synthetic()
        result = policy.members_for_permission(granted_roles)
        self.assertEqual(
            granted_roles,
            granted_before,
            f"输入角色列表在调用前后应一致，之前 {granted_before!r}，"
            f"之后 {granted_roles!r}",
        )
        self.assert_config_is_synthetic()
        return result

    # ---- 反查主流程 -----------------------------------------------------

    def test_full_lookup_matches_expected_members_and_roles(self):
        result = self.lookup(list(GRANTED_ROLES))
        self.assertEqual(
            result,
            EXPECTED_MEMBERS,
            f"反查 {GRANTED_ROLES!r} 的完整结果应为 {EXPECTED_MEMBERS!r}，"
            f"实际为 {result!r}",
        )

        # 每个命中成员只出现一次。
        members = [item["member"] for item in result]
        self.assertEqual(
            len(members),
            len(set(members)),
            f"命中成员不应重复，实际为 {members!r}",
        )
        # 成员按完整名称的 Unicode 码点升序，大小写原样保留。
        self.assertEqual(
            members,
            sorted(members),
            f"成员应按码点升序排列，实际为 {members!r}",
        )
        # 未获授的 writer（dave）与无角色成员（empty）不进入结果；
        # 无成员绑定的 ghost 不产生额外成员。
        self.assertNotIn("dave", members)
        self.assertNotIn("empty", members)
        self.assertNotIn("ghost", members)

        for item in result:
            # roles 仅含该成员实际获授的直接角色：去重并按码点升序。
            self.assertEqual(
                item["roles"],
                sorted(set(item["roles"])),
                f"成员 {item['member']!r} 的角色应去重并按码点升序，"
                f"实际为 {item['roles']!r}",
            )
        # alice 绑定 reader、editor、reader：去重后为 editor、reader。
        alice = next(item for item in result if item["member"] == "alice")
        self.assertEqual(alice["roles"], ["editor", "reader"])

    def test_input_order_and_duplicates_do_not_change_result(self):
        # 同一角色集合的不同排列与重复次数，结果完全一致。
        variants = [
            ["reader", "ghost", "editor", "reader"],
            ["editor", "reader"],
            ["ghost", "editor", "reader", "reader", "editor", "ghost"],
            ["reader", "editor"],
        ]
        for variant in variants:
            with self.subTest(granted_roles=variant):
                self.assertEqual(
                    self.lookup(list(variant)),
                    EXPECTED_MEMBERS,
                    f"输入 {variant!r} 的结果应与 {EXPECTED_MEMBERS!r} 一致",
                )

    def test_repeated_calls_return_identical_results(self):
        first = self.lookup(list(GRANTED_ROLES))
        second = self.lookup(list(GRANTED_ROLES))
        self.assertEqual(
            first,
            second,
            f"重复调用结果应一致，首次 {first!r}，再次 {second!r}",
        )
        self.assertEqual(first, EXPECTED_MEMBERS)

    # ---- 边界：空输入与精确匹配 -----------------------------------------

    def test_empty_granted_roles_returns_empty_list(self):
        self.assertEqual(
            self.lookup([]),
            [],
            "获授角色为空时应返回空列表",
        )

    def test_only_unbound_roles_returns_empty_list(self):
        for granted in (["ghost"], ["ghost", "phantom"]):
            with self.subTest(granted_roles=granted):
                self.assertEqual(
                    self.lookup(list(granted)),
                    [],
                    f"只有无成员绑定的角色 {granted!r} 时应返回空列表",
                )

    def test_role_names_match_exactly_without_normalization(self):
        # 这一层按名称精确匹配：不执行命令行的大小写敏感规整之外的
        # 任何处理——既不去首尾空白，也不做大小写折叠。
        for granted in (["Reader"], [" reader "]):
            with self.subTest(granted_roles=granted):
                self.assertEqual(
                    self.lookup(list(granted)),
                    [],
                    f"角色名 {granted!r} 不应匹配 reader（精确匹配，无规整）",
                )

    def test_ungranted_writer_and_roleless_member_never_appear(self):
        # 只授 writer：dave 命中，其余成员不出现——反向确认主场景中
        # dave 缺席确因 writer 未获授，而非成员被整体忽略。
        result = self.lookup(["writer"])
        self.assertEqual(
            result,
            [{"member": "dave", "roles": ["writer"]}],
            f"只授 writer 时应只得 dave，实际为 {result!r}",
        )
        # empty 无任何角色：任何获授输入下都不进入结果。
        for granted in (GRANTED_ROLES, ["writer"], ["reader", "writer", "editor"]):
            with self.subTest(granted_roles=granted):
                members = [item["member"] for item in self.lookup(list(granted))]
                self.assertNotIn(
                    "empty",
                    members,
                    f"无角色成员不应进入 {granted!r} 的反查结果",
                )

    # ---- 纯内存计算：不触碰存储 -----------------------------------------

    def test_lookup_creates_no_rule_files(self):
        # 在空临时目录中执行反查：纯内存计算不得创建任何规则文件。
        with tempfile.TemporaryDirectory() as tmpdir:
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            self.addCleanup(os.chdir, old_cwd)
            try:
                self.assertEqual(self.lookup(list(GRANTED_ROLES)), EXPECTED_MEMBERS)
                self.assertEqual(self.lookup([]), [])
            finally:
                os.chdir(old_cwd)
            self.assertEqual(
                os.listdir(tmpdir),
                [],
                f"纯内存反查不应创建规则文件，实际新增 {os.listdir(tmpdir)!r}",
            )


if __name__ == "__main__":
    unittest.main()
