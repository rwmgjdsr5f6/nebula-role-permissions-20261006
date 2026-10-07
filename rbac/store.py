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
    """授予角色权限；返回规则是否为本次实际新增。

    幂等性以“规整后的（角色, 权限）组合是否已存在”为准，而非依赖
    INSERT OR IGNORE：既有表可能带有与标准结构不同的唯一约束或检查约束，
    INSERT OR IGNORE 会把这类约束拒绝一并吞掉，在规则并未写入时仍报告
    成功。因此这里先做精确查询——组合已存在时按幂等成功直接返回；
    组合不存在时执行普通 INSERT 并提交，再复查该组合确实可被读出。
    只有目标规则实际持久保存才算成功；任何 sqlite3 失败（含唯一约束、
    检查约束阻止写入）或写入未生效都包装为 StorageError，原有授权、
    其他表与既有表结构保持不变。
    """
    try:
        existed = conn.execute(
            "SELECT 1 FROM role_permissions "
            "WHERE role = ? AND permission = ? LIMIT 1",
            (role, permission),
        ).fetchone()
        if existed is not None:
            return False
        cursor = conn.execute(
            "INSERT INTO role_permissions (role, permission) VALUES (?, ?)",
            (role, permission),
        )
        conn.commit()
        persisted = conn.execute(
            "SELECT 1 FROM role_permissions "
            "WHERE role = ? AND permission = ? LIMIT 1",
            (role, permission),
        ).fetchone()
    except sqlite3.Error as exc:
        # 约束拒绝或其他读写失败：丢弃未提交的部分写入，统一按存储失败上报。
        try:
            conn.rollback()
        except sqlite3.Error:
            pass
        raise StorageError(str(exc)) from exc
    if cursor.rowcount != 1 or persisted is None:
        # 普通 INSERT 成功提交后必然新增一行且可复查到；否则视为未持久保存。
        raise StorageError("grant did not persist the rule")
    return True


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


def list_roles_for_permission(conn, permission):
    """列出直接获授指定权限的全部角色；本函数只执行只读查询。

    权限按完整名称大小写敏感精确匹配（"*"、"%"、"_" 均为普通字符）；
    角色按保存名称原样返回，去重后按完整字符串的 Unicode 码点顺序升序排列；
    该权限从未授予（或授权已全部撤销）时返回空列表。角色是否配置了成员
    不影响结果。
    """
    try:
        rows = conn.execute(
            "SELECT role FROM role_permissions WHERE permission = ?",
            (permission,),
        ).fetchall()
    except sqlite3.Error as exc:
        raise StorageError(str(exc)) from exc
    return sorted({row[0] for row in rows})


def list_all_rules(conn):
    """导出库中现存的全部直接角色授权规则；本函数只执行只读查询。

    同一（角色, 权限）组合只出现一次；先按完整角色名的 Unicode 码点
    顺序升序排列，角色相同时再按完整权限名同样排序。名称按保存值
    原样返回，保留大小写，不再裁剪；"*"、"%"、"_" 均为普通字符。
    返回 (role, permission) 元组列表；空库返回空列表。
    """
    try:
        rows = conn.execute(
            "SELECT role, permission FROM role_permissions"
        ).fetchall()
    except sqlite3.Error as exc:
        raise StorageError(str(exc)) from exc
    return sorted({(row[0], row[1]) for row in rows})


def list_permissions_for_roles(conn, roles):
    """汇总多个角色当前已获授权限的去重合集；本函数只执行只读查询。

    权限按保存名称原样返回，去重后按完整字符串的 Unicode 码点顺序升序排列；
    角色列表为空或这些角色均无任何授权时返回空列表。
    """
    if not roles:
        return []
    placeholders = ",".join("?" for _ in roles)
    sql = "SELECT permission FROM role_permissions WHERE role IN (%s)" % placeholders
    try:
        rows = conn.execute(sql, list(roles)).fetchall()
    except sqlite3.Error as exc:
        raise StorageError(str(exc)) from exc
    return sorted({row[0] for row in rows})
