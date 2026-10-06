"""命令行入口：

    python -m rbac --db FILE grant ROLE PERMISSION
    python -m rbac --db FILE check MEMBER PERMISSION

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

    check_parser = subparsers.add_parser("check", help="查询成员是否拥有某权限")
    check_parser.add_argument("member")
    check_parser.add_argument("permission")
    return parser


def main(argv=None):
    # 确保中文原因在任何区域配置下都按 UTF-8 输出。
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8")

    args = _build_parser().parse_args(argv)

    if args.command == "grant":
        raw_names = (args.role, args.permission)
    else:
        raw_names = (args.member, args.permission)

    normalized = [policy.normalize_name(name) for name in raw_names]
    if any(name is None for name in normalized):
        # 不打开存储、不改动任何已有授权。
        _fail("invalid_name")
        return 2
    target_name, permission = normalized

    try:
        conn = store.connect(args.db)
    except store.StorageError:
        _fail("storage_error")
        return 1

    try:
        try:
            if args.command == "grant":
                store.grant_permission(conn, target_name, permission)
                result = {"role": target_name, "permission": permission}
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
