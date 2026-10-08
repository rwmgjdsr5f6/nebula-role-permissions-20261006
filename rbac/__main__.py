"""命令行入口：

    python -m rbac --db FILE grant ROLE PERMISSION
    python -m rbac --db FILE revoke ROLE PERMISSION
    python -m rbac --db FILE check MEMBER PERMISSION [--explain]
    python -m rbac --db FILE list-permissions ROLE
    python -m rbac --db FILE list-permission-roles PERMISSION
    python -m rbac --db FILE list-permission-members PERMISSION
    python -m rbac --db FILE list-role-members ROLE
    python -m rbac --db FILE list-member-permissions MEMBER [--explain]
    python -m rbac --db FILE list-roles
    python -m rbac --db FILE list-all-permissions
    python -m rbac --db FILE export-rules

退出码约定：
- 0：成功，标准输出为一个 JSON 对象；
- 2：名称去空白后为空，标准错误输出 {"error":"invalid_name"}；
- 1：数据库无法打开或读写失败，标准错误输出 {"error":"storage_error"}。
"""

import argparse
import json
import sys

from . import policy, store

# 紧凑分隔符，使错误输出与 {"error":"invalid_name"} 形态一致。
_SEPARATORS = (",", ":")


def _emit(obj):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False, separators=_SEPARATORS))
    sys.stdout.write("\n")


def _fail(error):
    sys.stderr.write(
        json.dumps({"error": error}, ensure_ascii=False, separators=_SEPARATORS)
    )
    sys.stderr.write("\n")


def _build_parser():
    parser = argparse.ArgumentParser(
        prog="rbac", description="本地角色权限规则库：直接角色授权与查询"
    )
    parser.add_argument("--db", required=True, help="SQLite 规则文件路径")
    subparsers = parser.add_subparsers(dest="command", required=True)

    grant_parser = subparsers.add_parser("grant", help="授予角色某个权限")
    grant_parser.add_argument("role")
    grant_parser.add_argument("permission")

    revoke_parser = subparsers.add_parser("revoke", help="撤销角色某个权限")
    revoke_parser.add_argument("role")
    revoke_parser.add_argument("permission")

    check_parser = subparsers.add_parser("check", help="查询成员是否拥有某权限")
    check_parser.add_argument("member")
    check_parser.add_argument("permission")
    check_parser.add_argument(
        "--explain",
        action="store_true",
        help="额外输出实际直接获授请求权限的成员固定角色（granted_roles）",
    )

    list_parser = subparsers.add_parser(
        "list-permissions", help="列出角色直接获授的全部权限"
    )
    list_parser.add_argument("role")

    member_list_parser = subparsers.add_parser(
        "list-member-permissions", help="汇总成员直接角色当前拥有的全部权限"
    )
    member_list_parser.add_argument("member")
    member_list_parser.add_argument(
        "--explain",
        action="store_true",
        help="额外输出每项权限的获授来源角色（sources）",
    )

    permission_roles_parser = subparsers.add_parser(
        "list-permission-roles", help="列出直接获授某权限的全部角色"
    )
    permission_roles_parser.add_argument("permission")

    permission_members_parser = subparsers.add_parser(
        "list-permission-members",
        help="按直接授权与固定成员关系列出某项权限的获准成员",
    )
    permission_members_parser.add_argument("permission")

    role_members_parser = subparsers.add_parser(
        "list-role-members",
        help="按固定成员关系列出直接绑定某角色的全部合成成员",
    )
    role_members_parser.add_argument("role")

    subparsers.add_parser(
        "list-roles", help="列出当前至少持有一条直接授权的全部角色"
    )
    subparsers.add_parser(
        "list-all-permissions",
        help="列出当前至少被一个角色直接获授的全部权限名",
    )
    subparsers.add_parser(
        "export-rules", help="导出库中现存的全部直接角色授权规则"
    )
    return parser


def main(argv=None):
    # 确保中文原因在任何区域配置下都按 UTF-8 输出。
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8")

    args = _build_parser().parse_args(argv)

    if args.command in ("export-rules", "list-roles", "list-all-permissions"):
        # 不接收成员、角色或权限参数，无需名称校验。
        raw_names = ()
    elif args.command in ("grant", "revoke"):
        raw_names = (args.role, args.permission)
    elif args.command == "list-permissions":
        raw_names = (args.role,)
    elif args.command == "list-permission-roles":
        raw_names = (args.permission,)
    elif args.command == "list-permission-members":
        raw_names = (args.permission,)
    elif args.command == "list-role-members":
        raw_names = (args.role,)
    elif args.command == "list-member-permissions":
        raw_names = (args.member,)
    else:
        raw_names = (args.member, args.permission)

    normalized = [policy.normalize_name(name) for name in raw_names]
    if any(name is None for name in normalized):
        # 不打开存储、不改动任何已有授权。
        _fail("invalid_name")
        return 2
    target_name = normalized[0] if normalized else None
    permission = normalized[1] if len(normalized) > 1 else None

    try:
        conn = store.connect(args.db)
    except store.StorageError:
        _fail("storage_error")
        return 1

    try:
        try:
            if args.command == "export-rules":
                rules = store.list_all_rules(conn)
                result = {
                    "rules": [
                        {"role": role, "permission": permission}
                        for role, permission in rules
                    ]
                }
            elif args.command == "list-roles":
                result = {"roles": store.list_roles(conn)}
            elif args.command == "list-all-permissions":
                result = {"permissions": store.list_all_permissions(conn)}
            elif args.command == "grant":
                store.grant_permission(conn, target_name, permission)
                result = {"role": target_name, "permission": permission}
            elif args.command == "revoke":
                revoked = store.revoke_permission(conn, target_name, permission)
                result = {
                    "role": target_name,
                    "permission": permission,
                    "revoked": revoked,
                }
            elif args.command == "list-permissions":
                permissions = store.list_permissions(conn, target_name)
                result = {"role": target_name, "permissions": permissions}
            elif args.command == "list-permission-roles":
                # 单参数子命令：规整后的权限名即 target_name。
                roles = store.list_roles_for_permission(conn, target_name)
                result = {"permission": target_name, "roles": roles}
            elif args.command == "list-permission-members":
                # 先按直接授权反查角色，再经固定成员关系收敛为获准成员。
                roles = store.list_roles_for_permission(conn, target_name)
                members = policy.members_for_permission(roles)
                result = {"permission": target_name, "members": members}
            elif args.command == "list-role-members":
                # 结果只取决于固定成员关系；连接仍按既有行为打开并初始化
                # （文件缺失且父目录可写时创建空库），但不查询任何授权。
                members = policy.members_for_role(target_name)
                result = {"role": target_name, "members": members}
            elif args.command == "list-member-permissions":
                roles = policy.roles_for(target_name)
                if args.explain:
                    # permissions 与 sources 取自同一次、且只按成员固定
                    # 角色范围的查询：sources 与 permissions 一一对应，
                    # 每项来源角色都确实绑定于该成员并获授对应权限，
                    # 因而不会出现空来源项。
                    permission_roles = store.list_permission_roles_for_roles(
                        conn, roles
                    )
                    permissions = list(permission_roles.keys())
                    result = {
                        "member": target_name,
                        "roles": roles,
                        "permissions": permissions,
                        "sources": [
                            {"permission": permission, "roles": source_roles}
                            for permission, source_roles in permission_roles.items()
                        ],
                    }
                else:
                    permissions = store.list_permissions_for_roles(conn, roles)
                    result = {
                        "member": target_name,
                        "roles": roles,
                        "permissions": permissions,
                    }
            else:
                # 角色只解析一次：存储匹配与决定中的角色说明共用同一次
                # roles_for 结果，避免重复处理造成两者不一致。
                roles = policy.roles_for(target_name)
                if args.explain:
                    # 允许与否及来源角色取自同一次、且只按成员固定角色
                    # 范围的查询：granted_roles 中的角色必然同时满足
                    # “绑定于该成员”与“确实直接获授请求权限”，故其他
                    # 角色（即使同获授该权限）不出现，allowed 与
                    # granted_roles 非空也必然一致。
                    granted_roles = store.list_granted_roles_for_permission(
                        conn, roles, permission
                    )
                    result = policy.decide(
                        target_name,
                        permission,
                        bool(granted_roles),
                        roles=roles,
                        granted_roles=granted_roles,
                    )
                else:
                    granted = store.permission_granted(conn, roles, permission)
                    result = policy.decide(
                        target_name, permission, granted, roles=roles
                    )
        except store.StorageError:
            _fail("storage_error")
            return 1
    finally:
        conn.close()

    _emit(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
