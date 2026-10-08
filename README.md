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

## 按角色查询固定成员

`list-role-members` 直接查看某角色当前固定关联的合成成员，结果只取决于源码中的固定成员关系，与库中的授权无关：

```console
$ python -m rbac --db rules.db list-role-members reader
{"role":"reader","members":["alice"]}
$ python -m rbac --db rules.db list-role-members editor
{"role":"editor","members":[]}
```

`editor` 未绑定任何固定成员，空数组是正常空结果（退出码 0），不是执行失败；`Reader` 不会匹配 `reader`。成员名保留配置原值，去重后按完整名称的 Unicode 码点升序排列。

## 成员权限汇总与授权来源

`list-member-permissions` 汇总某成员固定绑定的直接角色当前拥有的全部权限：

```console
$ python -m rbac --db rules.db list-member-permissions alice
{"member":"alice","roles":["reader"],"permissions":["documents:read"]}
```

加上可选的 `--explain` 开关后，输出仅额外增加一个 `sources` 数组，与 `permissions` 一一对应，给出每项权限来自该成员的哪些固定角色：

```console
$ python -m rbac --db rules.db list-member-permissions alice --explain
{"member":"alice","roles":["reader"],"permissions":["documents:read"],"sources":[{"permission":"documents:read","roles":["reader"]}]}
```

来源只包含成员固定绑定、且确实获授对应权限的角色。上例中即使 `editor` 也获授了 `documents:read`，由于 `alice` 只固定绑定 `reader`，`sources` 中不会出现 `editor`；撤销 `reader` 的这条授权后，`permissions` 与 `sources` 均为空，而 `roles` 仍为 `["reader"]`。未配置的成员（如 `bob` 或大小写不同的 `Alice`）返回空的 `roles`、`permissions`、`sources`。不带 `--explain` 时输出保持 `member`、`roles`、`permissions` 三个字段不变。权限名与角色名均去重，按完整名称的 Unicode 码点升序排列，保存值、大小写与内部空白原样保留，`*`、`%`、`_` 均为普通字符。

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
python -m rbac --db FILE list-role-members ROLE
python -m rbac --db FILE list-member-permissions MEMBER [--explain]
python -m rbac --db FILE list-roles
python -m rbac --db FILE list-all-permissions
python -m rbac --db FILE export-rules
```

所有命令成功时退出码为 0，标准输出为一行 JSON；退出码 2 与 1 的含义见上节。
