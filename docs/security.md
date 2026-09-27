# 安全模型

root Supervisor 只负责生命周期、私有挂载命名空间和进程不变量，不解析登录业务数据。
因此 backend unit 必须保留 `User=root`，不能将整个服务降权成 Broker 账户。
三个子角色由 systemd-sysusers 创建命名系统账户，Supervisor 经 NSS 解析 UID/GID 后
使用 setpriv 启动；不存在固定的数字 UID 要求。

| 角色 | 账户 | capabilities（全部集合） | NoNewPrivileges |
|---|---|---|---|
| Broker | inode-modern-broker | 0 | 1 |
| Engine | inode-modern-engine | CAP_NET_RAW、CAP_NET_ADMIN | 1 |
| Mon | inode-modern-mon | 0 | 1 |

验证角色 UID/GID、主组、补充组、不可登录 shell、不可共享身份、NSS 一致性，
并继续验证精确进程数量、固定 generation 中的可执行文件、cgroup、UDP 所有权和权限集合。
角色错位、额外权限、NNP 缺失均 fail closed。未知进程身份不能推断为可信角色。

认证组件处于同一 systemd 故障域；专属 nftables 表保护原厂 UDP 端口，
客户端只通过 Unix socket 与无 capabilities 的 Broker 通信。
原厂文件通过安全 importer 写入 root 拥有、不可由普通用户修改的 generation；
完整 manifest 和符号链接边界验证在激活及启动时执行。

setup 不执行原厂安装脚本；下载和手动导入均必须匹配公开的受支持版本 metadata。
本项目不声称原厂闭源组件本身不存在安全问题。
