"""直接角色授权与查询的核心逻辑（仅 Python 3 标准库 + SQLite）。"""

import sqlite3

# 固定成员及其直接角色；本版本不支持成员管理或角色继承。
FIXED_MEMBER_ROLES = {"alice": ("reader",)}

REASON_GRANTED = "直接角色授权"
REASON_DENIED = "权限未授予"
REASON_UNKNOWN_MEMBER = "成员未配置"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS role_permissions (
    role TEXT NOT NULL,
    permission TEXT NOT NULL,
    PRIMARY KEY (role, permission)
)
"""


def normalize_name(name):
    """去除首尾空白；去除后为空的名称视为无效。"""
    normalized = name.strip()
    if not normalized:
        raise ValueError("invalid_name")
    return normalized


def _connect(db_path):
    conn = sqlite3.connect(db_path)
    conn.execute(_SCHEMA)
    return conn


def grant(db_path, role, permission):
    """保存一条角色-权限规则；重复授权不产生重复规则。"""
    role = normalize_name(role)
    permission = normalize_name(permission)
    with _connect(db_path) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO role_permissions (role, permission) VALUES (?, ?)",
            (role, permission),
        )
    return {"role": role, "permission": permission}


def check(db_path, member, permission):
    """查询成员是否被允许某权限；只读，不增删任何授权规则。"""
    member = normalize_name(member)
    permission = normalize_name(permission)
    roles = list(FIXED_MEMBER_ROLES.get(member, ()))
    if not roles:
        return {
            "member": member,
            "permission": permission,
            "roles": [],
            "allowed": False,
            "reason": REASON_UNKNOWN_MEMBER,
        }
    with _connect(db_path) as conn:
        granted = {
            row[0]
            for row in conn.execute(
                "SELECT permission FROM role_permissions WHERE role IN (%s)"
                % ",".join("?" * len(roles)),
                roles,
            )
        }
    allowed = permission in granted
    return {
        "member": member,
        "permission": permission,
        "roles": roles,
        "allowed": allowed,
        "reason": REASON_GRANTED if allowed else REASON_DENIED,
    }
