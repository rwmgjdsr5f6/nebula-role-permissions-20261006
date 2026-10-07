"""命令行入口：

    python -m rbac --db FILE grant ROLE PERMISSION
    python -m rbac --db FILE revoke ROLE PERMISSION
    python -m rbac --db FILE check MEMBER PERMISSION
    python -m rbac --db FILE list-permissions ROLE
    python -m rbac --db FILE list-permission-roles PERMISSION
    python -m rbac --db FILE list-permission-members PERMISSION
    python -m rbac --db FILE list-member-permissions MEMBER
    python -m rbac --db FILE list-roles
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

    list_parser = subparsers.add_parser(
        "list-permissions", help="列出角色直接获授的全部权限"
    )
    list_parser.add_argument("role")

    member_list_parser = subparsers.add_parser(
        "list-member-permissions", help="汇总成员直接角色当前拥有的全部权限"
    )
    member_list_parser.add_argument("member")

    permission_roles_parser = subparsers.add_parser(
        "list-permission-roles", help="列出直接获授某权限的全部角色"
    )
    permission_roles_parser.add_argument("permission")

    permission_members_parser = subparsers.add_parser(
        "list-permission-members",
        help="按直接授权与固定成员关系列出某项权限的获准成员",
    )
    permission_members_parser.add_argument("permission")

    subparsers.add_parser(
        "list-roles", help="列出库中当前至少持有一条授权的全部角色"
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

    if args.command in ("export-rules", "list-roles"):
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
                roles = store.list_all_roles(conn)
                result = {"roles": roles}
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
            elif args.command == "list-member-permissions":
                roles = policy.roles_for(target_name)
                permissions = store.list_permissions_for_roles(conn, roles)
                result = {
                    "member": target_name,
                    "roles": roles,
                    "permissions": permissions,
                }
            else:
                granted = store.permission_granted(
                    conn, policy.roles_for(target_name), permission
                )
                result = policy.decide(target_name, permission, granted)
        except store.StorageError:
            _fail("storage_error")
            return 1
    finally:
        conn.close()

    _emit(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
