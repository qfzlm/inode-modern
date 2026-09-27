# 安装、维护与迁移

公共 RPM 使用 `/usr/bin`、`/usr/libexec/inode-modern`、`/usr/share` 和
`/usr/lib/systemd/system`。软件包不携带原厂文件，不自动下载、不自动启用认证。
首次执行 setup 完成官方包验证和 generation 激活后才启用服务。

## 已有本地开发版

如果 `/etc/systemd/system` 中存在本项目自定义 unit，RPM 应拒绝直接覆盖安装。
先备份原安装，安排可接受的断网时间并完成明确的迁移；不要在正在使用的校园认证
连接上试装 RPM。不要删除或覆盖现有私有恢复资料。
当前发行测试不包含对既有开发机的在线切换。

## 更新与重装

同版本重装及升级保留 `/opt/inode-modern` 的原厂 generations、账户和凭据。
不自动重新认证或重启活动 backend。若需要使用更新的运行时代码，先保存工作，
再由管理员明确重启服务，然后由用户按需重新连接。
重复执行无参数 setup 会校验已配置 generation，且不会重启活动服务。
带新输入的 setup 在 backend 活跃时拒绝替换。

## 卸载

卸载停止 backend/firewall 并清理 `inet inode_modern_guard`，停止失败则拒绝继续清理。
这会终止认证，请安排合适时间。原厂 generations、系统账户及钱包条目保留：
避免错误删除用户自行获取的软件或使已有文件 UID 指向他人。
如需彻底清理，应先确认没有进程使用这些文件，再由管理员有意识地处理。
