# 本地角色权限规则库

管理角色到权限的直接授权规则，并按固定的成员-角色关系判定成员是否拥有某项权限。面向本地单机使用，仅依赖 Python 3 标准库与 SQLite，无需安装任何第三方包。

## 数据模型

- SQLite 规则文件只保存一类数据：**角色 -> 权限** 的直接授权规则。
- 成员与角色的对应关系**固定在源码中**（`rbac/policy.py` 的 `FIXED_MEMBER_ROLES`）：`alice` 绑定角色 `reader`。该关系不入库，任何命令都无法修改。
- 本产品不包含登录、成员管理或角色继承功能；判定只依据直接角色授权。

## 快速上手

在仓库根目录执行以下两步。前提：当前目录（规则文件的父目录）存在，且 `rules.db` 尚不存在——首次调用会自动创建该规则文件。

第一步，授予角色 `reader` 权限 `documents:read`：

```console
$ python -m rbac --db rules.db grant reader documents:read
{"role":"reader","permission":"documents:read"}
```

第二步，查询成员 `alice` 是否拥有权限 `documents:read`：

```console
$ python -m rbac --db rules.db check alice documents:read
{"member":"alice","permission":"documents:read","roles":["reader"],"allowed":true,"reason":"直接角色授权"}
```

`alice` 被允许，原因是她固定的直接角色 `reader` 已获授该权限。

两步均以退出码 0 结束，标准错误为空，标准输出为一行 UTF-8 编码的 JSON（带末尾换行）。重复执行相同的 `grant` 是幂等的：规则已存在时不新增记录，库中始终只有一条 `(reader, documents:read)`。

## 正常拒绝与执行失败

`check` 的拒绝是正常业务结果，仍以退出码 0 结束，不要与执行失败混淆。

成员已配置、但其角色未获授该权限：

```console
$ python -m rbac --db rules.db check alice documents:write
{"member":"alice","permission":"documents:write","roles":["reader"],"allowed":false,"reason":"权限未授予"}
```

成员未配置（固定关系中没有该成员）：

```console
$ python -m rbac --db rules.db check bob documents:read
{"member":"bob","permission":"documents:read","roles":[],"allowed":false,"reason":"成员未配置"}
```

`check` 等查询命令不改动任何授权记录；但如果规则文件尚不存在且父目录可写，首次调用（包括查询）仍会创建该文件。

## 名称规则

所有成员名、角色名、权限名先去除首尾空白，再按完整字符串做**大小写敏感**的精确匹配。

## 执行失败

失败时标准输出为空，标准错误输出一行 JSON 错误对象。

- **名称无效**（退出码 2）：任一名称去空白后为空（空字符串或纯空白），标准错误为 `{"error":"invalid_name"}`。名称校验优先于一切存储操作——此时不会打开或创建数据库文件。
- **存储失败**（退出码 1）：名称有效，但规则文件无法打开或读写，例如父目录不存在、或目标路径不是 SQLite 数据库文件，标准错误为 `{"error":"storage_error"}`。

## 全部命令

```text
python -m rbac --db FILE grant ROLE PERMISSION
python -m rbac --db FILE revoke ROLE PERMISSION
python -m rbac --db FILE check MEMBER PERMISSION
python -m rbac --db FILE list-permissions ROLE
python -m rbac --db FILE list-permission-roles PERMISSION
python -m rbac --db FILE list-permission-members PERMISSION
python -m rbac --db FILE list-member-permissions MEMBER
python -m rbac --db FILE list-roles
python -m rbac --db FILE list-all-permissions
python -m rbac --db FILE export-rules
```

所有命令成功时退出码为 0，标准输出为一行 JSON；退出码 2 与 1 的含义见上节。
