"""命令行入口：python -m rbac --db <文件> grant|check ..."""

import argparse
import json
import sqlite3
import sys

from .core import check, grant


def _emit_error(message, exit_code):
    sys.stderr.write(json.dumps({"error": message}, separators=(",", ":")) + "\n")
    return exit_code


def main(argv=None):
    parser = argparse.ArgumentParser(prog="rbac")
    parser.add_argument("--db", required=True, help="SQLite 数据库文件路径")
    subparsers = parser.add_subparsers(dest="command", required=True)

    grant_parser = subparsers.add_parser("grant", help="授予角色某权限")
    grant_parser.add_argument("role")
    grant_parser.add_argument("permission")

    check_parser = subparsers.add_parser("check", help="查询成员是否被允许某权限")
    check_parser.add_argument("member")
    check_parser.add_argument("permission")

    args = parser.parse_args(argv)

    try:
        if args.command == "grant":
            result = grant(args.db, args.role, args.permission)
        else:
            result = check(args.db, args.member, args.permission)
    except ValueError:
        return _emit_error("invalid_name", 2)
    except (sqlite3.Error, OSError):
        return _emit_error("storage_error", 1)

    sys.stdout.write(json.dumps(result, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
