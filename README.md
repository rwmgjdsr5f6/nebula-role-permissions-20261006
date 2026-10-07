# 本地角色权限规则库

面向本地单机的角色权限规则管理：直接角色授权、访问判定、查询与规则导出。

- 运行只需 **Python 3 标准库**与 **SQLite**（由 Python 自带的 `sqlite3` 模块提供），无需安装任何第三方依赖。
- 规则文件（SQLite 数据库）**只保存“角色 → 权限”的直接授权**。
- 成员与角色的对应关系是**源码中的固定数据**，不入库、不可通过命令修改；当前固定关系仅为 `alice → reader`（见 `rbac/policy.py`）。
- 不存在登录、成员管理、角色继承等功能。

## 快速开始（两步样例）

在**仓库根目录**下执行（前提：当前目录即父目录且可写，`rules.db` 尚不存在）。

第一步，把 `documents:read` 授予角色 `reader`：

```sh
python -m rbac --db rules.db grant reader documents:read
```

标准输出（一行 UTF-8 JSON，带末尾换行）：

```json
{"role":"reader","permission":"documents:read"}
```

第二步，查询成员 `alice` 是否拥有 `documents:read`：

```sh
python -m rbac --db rules.db check alice documents:read
```

标准输出：

```json
{"member":"alice","permission":"documents:read","roles":["reader"],"allowed":true,"reason":"直接角色授权"}
```

两步均**退出码 0、标准错误为空**，标准输出各为一行 UTF-8 JSON 并带末尾换行。

由此即可确认 alice 的权限与允许原因：`alice` 的角色 `reader` 固定在源码中，而 `reader` 已在规则库里直接获授 `documents:read`，故 `allowed` 为 `true`，`reason` 为“直接角色授权”。

说明：

- **首次调用会创建规则文件** `rules.db`（并在其中建立授权表）；文件所在的父目录必须事先存在。
- `grant` 是幂等的：重复执行同一条授权，输出不变，规则也不会重复增加。
- 再次执行 `python -m rbac --db rules.db export-rules` 可看到库中现存的全部授权，例如：
  `{"rules":[{"role":"reader","permission":"documents:read"}]}`。

## 正常拒绝与执行失败的区别

“拒绝”是正常的判定结果，仍然退出 0 并在标准输出给出 JSON；“执行失败”才使用非 0 退出码并把错误写到标准错误。

### 正常拒绝（退出 0）

- `alice` 查询一个**未授予其角色**的权限 `documents:write`：

  ```sh
  python -m rbac --db rules.db check alice documents:write
  ```

  ```json
  {"member":"alice","permission":"documents:write","roles":["reader"],"allowed":false,"reason":"权限未授予"}
  ```

- 非固定成员 `bob` 查询 `documents:read`：其角色列表为空。

  ```sh
  python -m rbac --db rules.db check bob documents:read
  ```

  ```json
  {"member":"bob","permission":"documents:read","roles":[],"allowed":false,"reason":"成员未配置"}
  ```

两种情况都退出 0、标准错误为空。

### 执行失败（非 0 退出，标准输出为空）

所有名称参数（成员、角色、权限）都遵循同一规整顺序：**先去除首尾空白，再按大小写敏感的完整名称精确匹配**（不做大小写折叠，`*`、`%`、`_` 均为普通字符）。

- 规整后名称为空（空名称或纯空白名称）：**退出 2**，不打开数据库，标准错误为一行

  ```json
  {"error":"invalid_name"}
  ```

- 名称有效，但规则文件无法正常使用，例如**父目录不存在**或目标文件**不是 SQLite 文件**：**退出 1**，标准错误为一行

  ```json
  {"error":"storage_error"}
  ```

两类失败的标准输出都为空；名称错误优先判定，且不会打开或创建数据库。

注意：查询类命令不会修改任何授权记录，但只要名称有效就会打开数据库——**当数据库文件缺失时，查询也可能先创建一个空的规则文件**（例如对缺失的库执行 `check`），随后再返回正常的查询结果。

## 命令一览与输出格式

所有命令统一形式为 `python -m rbac --db FILE <子命令> [参数...]`。成功时退出 0，标准输出为一行紧凑 JSON（无多余空格，UTF-8，带末尾换行）。

| 命令 | 说明 | 成功时标准输出 |
| --- | --- | --- |
| `grant ROLE PERMISSION` | 授予角色某权限（幂等） | `{"role":...,"permission":...}` |
| `revoke ROLE PERMISSION` | 撤销角色某权限 | `{"role":...,"permission":...,"revoked":布尔}` |
| `check MEMBER PERMISSION` | 判定成员是否拥有某权限 | `{"member","permission","roles","allowed","reason"}` |
| `list-permissions ROLE` | 列出角色直接获授的全部权限 | `{"role":...,"permissions":[...]}` |
| `list-permission-roles PERMISSION` | 列出直接获授某权限的全部角色 | `{"permission":...,"roles":[...]}` |
| `list-permission-members PERMISSION` | 按直接授权与固定成员关系列获准成员 | `{"permission":...,"members":[{"member":...,"roles":[...]}]}` |
| `list-member-permissions MEMBER` | 汇总成员直接角色当前拥有的全部权限 | `{"member","roles":[...],"permissions":[...]}` |
| `list-roles` | 列出持有至少一条授权的全部角色 | `{"roles":[...]}` |
| `list-all-permissions` | 列出至少被一个角色获授的全部权限 | `{"permissions":[...]}` |
| `export-rules` | 导出全部现存直接角色授权规则 | `{"rules":[{"role":...,"permission":...}]}` |

列表类结果中的名称按保存值原样返回（保留大小写与内部空白），去重后按完整名称的 Unicode 码点顺序升序排列。

退出码约定：

- `0`：成功（包括 `allowed` 为 `false` 的正常拒绝），结果 JSON 在标准输出；
- `2`：名称去空白后为空，标准错误为 `{"error":"invalid_name"}`；
- `1`：数据库无法打开或读写失败，标准错误为 `{"error":"storage_error"}`。
