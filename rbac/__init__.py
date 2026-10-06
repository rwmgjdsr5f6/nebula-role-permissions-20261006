"""本地角色权限规则库：固定成员的直接角色授权与查询。"""

from .core import FIXED_MEMBER_ROLES, check, grant

__all__ = ["FIXED_MEMBER_ROLES", "grant", "check"]
