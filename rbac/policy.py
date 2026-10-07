"""固定成员的直接角色、名称规整与判定原因。"""

# 判定原因（对外输出的固定文案）。
REASON_ALLOWED = "直接角色授权"
REASON_PERMISSION_NOT_GRANTED = "权限未授予"
REASON_MEMBER_NOT_CONFIGURED = "成员未配置"

# 合成固定成员 -> 直接角色列表。
# 不存在登录、角色继承或成员管理；grant 只保存“角色 -> 权限”规则，
# 无法改变这里的对应关系。
FIXED_MEMBER_ROLES = {
    "alice": ("reader",),
}


def normalize_name(name):
    """名称先去除首尾空白，再按完整字符串大小写敏感匹配。

    去除空白后为空返回 None，由调用方按 invalid_name 处理。
    """
    if name is None:
        return None
    trimmed = name.strip()
    return trimmed if trimmed else None


def roles_for(member):
    """返回成员的直接角色；非固定成员返回空列表。"""
    roles = FIXED_MEMBER_ROLES.get(member)
    return list(roles) if roles is not None else []


def members_for_permission(granted_roles):
    """按固定成员关系反查直接获授某权限的成员。

    granted_roles 为直接获授该权限的角色名集合。返回成员项列表，每项含
    member 及该成员直接获授该权限的 roles（去重后按 Unicode 码点升序）；
    成员按名称码点升序排列，不重复。未绑定任何固定成员的角色不产生成员项；
    没有成员命中时返回空列表。
    """
    granted = set(granted_roles)
    members = []
    for member in sorted(FIXED_MEMBER_ROLES):
        roles = sorted(
            {role for role in FIXED_MEMBER_ROLES[member] if role in granted}
        )
        if roles:
            members.append({"member": member, "roles": roles})
    return members


def decide(member, permission, granted):
    """依据成员角色与规则匹配结果生成决定。

    granted 表示该成员的任一直接角色是否直接拥有请求的权限。
    """
    roles = roles_for(member)
    if not roles:
        allowed = False
        reason = REASON_MEMBER_NOT_CONFIGURED
    elif granted:
        # 直接角色与请求权限共同说明允许原因。
        allowed = True
        reason = REASON_ALLOWED
    else:
        allowed = False
        reason = REASON_PERMISSION_NOT_GRANTED
    return {
        "member": member,
        "permission": permission,
        "roles": roles,
        "allowed": allowed,
        "reason": reason,
    }
