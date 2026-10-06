# 本地角色权限规则库

管理角色、权限与访问规则。面向本地单机使用，采用 Python 3 标准库与 SQLite。

当前实现：固定成员 alice（仅 reader 角色）的直接角色授权与查询。

## 用法

```sh
# 授予角色某权限（幂等，重复授权不产生重复规则）
python -m rbac --db demo.db grant reader documents:read

# 查询成员是否被允许某权限（只读）
python -m rbac --db demo.db check alice documents:read
```

- 成功时退出 0，标准输出为单个 JSON 对象。
- 名称去除首尾空白后为空：退出 2，标准错误输出 `{"error":"invalid_name"}`。
- 数据库无法打开或读写失败：退出 1，标准错误输出 `{"error":"storage_error"}`。
