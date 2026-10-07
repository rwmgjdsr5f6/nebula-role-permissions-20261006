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
    """按直接获授角色与固定成员关系反查获准成员；纯内存计算，不访问存储。

    granted_roles 为直接获授目标权限的全部角色。只有固定成员配置中
    至少绑定其中一个角色的成员才进入结果；没有成员的角色被忽略。
    成员项形如 {"member": 成员名, "roles": 该成员直接获授该权限的角色}，
    名称按保存值原样返回、保留大小写；成员不重复，roles 去重，成员与
    角色分别按完整名称的 Unicode 码点顺序升序排列；无成员命中时返回空列表。
    """
    granted = set(granted_roles)
    members = {}
    for member, roles in FIXED_MEMBER_ROLES.items():
        matched = sorted(granted.intersection(roles))
        if matched:
            members[member] = matched
    return [
        {"member": member, "roles": members[member]} for member in sorted(members)
    ]


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
