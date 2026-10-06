"""SQLite 持久化层：角色到权限的直接授权规则。

数据库中只保存“角色 -> 权限”这一类规则；固定成员与角色的对应关系
不属于可管理数据，不入库（见 policy.FIXED_MEMBER_ROLES）。
"""

import sqlite3

_SCHEMA = """
CREATE TABLE IF NOT EXISTS role_permissions (
    role       TEXT NOT NULL,
    permission TEXT NOT NULL,
    PRIMARY KEY (role, permission)
)
"""


class StorageError(Exception):
    """数据库无法打开或读写失败。"""


def connect(db_path):
    """打开（必要时创建）规则文件并确保表结构就绪。

    任何 sqlite3 层面的失败统一包装为 StorageError。
    """
    try:
        conn = sqlite3.connect(db_path)
    except sqlite3.Error as exc:
        raise StorageError(str(exc)) from exc
    try:
        conn.execute(_SCHEMA)
        conn.commit()
    except sqlite3.Error as exc:
        conn.close()
        raise StorageError(str(exc)) from exc
    return conn


def grant_permission(conn, role, permission):
    """授予角色权限；规则已存在时不产生重复行（INSERT OR IGNORE）。"""
    try:
        conn.execute(
            "INSERT OR IGNORE INTO role_permissions (role, permission) VALUES (?, ?)",
            (role, permission),
        )
        conn.commit()
    except sqlite3.Error as exc:
        raise StorageError(str(exc)) from exc


def revoke_permission(conn, role, permission):
    """撤销角色的单个权限；返回是否实际删除了已有规则。

    只删除（角色, 权限）精确对应的一行；规则不存在时不报错，
    也不影响其他角色或权限的授权。
    """
    try:
        cursor = conn.execute(
            "DELETE FROM role_permissions WHERE role = ? AND permission = ?",
            (role, permission),
        )
        conn.commit()
    except sqlite3.Error as exc:
        raise StorageError(str(exc)) from exc
    return cursor.rowcount > 0


def permission_granted(conn, roles, permission):
    """任一直接角色拥有该权限即为 True；本函数只执行只读查询。"""
    if not roles:
        return False
    placeholders = ",".join("?" for _ in roles)
    sql = (
        "SELECT 1 FROM role_permissions "
        "WHERE permission = ? AND role IN (%s) LIMIT 1" % placeholders
    )
    try:
        row = conn.execute(sql, [permission] + list(roles)).fetchone()
    except sqlite3.Error as exc:
        raise StorageError(str(exc)) from exc
    return row is not None


def list_permissions(conn, role):
    """列出角色直接获授的全部权限；本函数只执行只读查询。

    权限按保存名称原样返回，去重后按完整字符串的 Unicode 码点顺序升序排列；
    角色没有任何授权（含角色从未出现）时返回空列表。
    """
    try:
        rows = conn.execute(
            "SELECT permission FROM role_permissions WHERE role = ?",
            (role,),
        ).fetchall()
    except sqlite3.Error as exc:
        raise StorageError(str(exc)) from exc
    return sorted({row[0] for row in rows})
