# iNode Modern

适用于西南财经大学有线校园网的原生 Qt 桌面客户端和命令行工具。
它以独立的低权限 Broker 连接 H3C iNode 原厂认证引擎，提供清晰的连接状态、
网卡与 IPv4 信息、KDE 钱包密码保存和手动连接/断开操作。

**首个公开 beta：v0.2.0-beta.1。当前目标是 Fedora 44 x86_64，主要桌面验证环境为 KDE / Wayland。**
其他发行版、其他学校、无线网络和其他原厂版本未获验证。
本项目与西南财经大学、H3C 均无官方隶属关系。

## 安装

从本项目 GitHub Releases 下载 RPM 和 SHA256SUMS，先核对摘要，再安装：

```sh
sha256sum --ignore-missing -c SHA256SUMS
sudo dnf install ./inode-modern-*.x86_64.rpm
sudo inode-modern-setup
```

RPM 只安装 inode-modern 自有组件。H3C/iNode 是第三方 proprietary software，
不属于 MIT，不随仓库、RPM 或 Release 分发。
原厂软件下载入口：[西财官方客户端下载页面](https://info.swufe.edu.cn/info/1027/2411.htm)。

setup 从官方页面解析 `iNodeClient_Linux64_7.3 (E0538).tar.zip`，仅接受 metadata
中已核对 SHA256 的版本。所有重定向也必须留在 `info.swufe.edu.cn` HTTPS 域名内。
页面变化、未知版本、哈希不匹配都会停止；不会猜附件地址或运行原厂安装脚本。
若下载失败，请在浏览器中打开官方页面下载，然后手动导入：

```sh
sudo inode-modern-setup --vendor-archive '/path/to/iNodeClient_Linux64_7.3 (E0538).tar.zip'
# 也接受该已验证包中的原始 tar.gz，或原始解压目录：
sudo inode-modern-setup --vendor-dir /path/to/iNodeClient
```

导入复用安全 generation 管理器，写入 `/opt/inode-modern/vendor/gen-NNNN` 并生成完整
SHA256 manifest；验证后才切换 `/opt/inode-modern/current`，启用并启动服务。
未配置原厂组件时服务不反复启动，GUI/CLI 会提示运行 setup。
已有认证进程时 setup 不会替你断开或杀进程；已有本地开发版安装需先阅读
[迁移说明](docs/installation.md)。

## GUI 使用

从 KDE 启动器打开 **iNode Modern**，选择有线网卡，填写校园网账号和密码后连接。
左侧显示有线链路、校园网认证、网络地址三个独立阶段；“已连接”表示认证成功，
不等同于已验证公网。关闭窗口不主动断开认证。

密码默认不保存。需要保存时使用“密码保存设置”；仅通过 KDE Wallet 安全保存。
钱包不可用时提示失败，不降级写入明文。不要用 sudo 启动 GUI。

## CLI

```sh
inode-modern status
inode-modern connect --help
inode-modern disconnect
```

连接命令通过交互方式读取密码；不要把密码放在 shell 命令行或脚本中。
CLI 和 GUI 使用相同的普通用户控制接口。断开操作会结束校园网认证。

## 升级和卸载

```sh
sudo dnf upgrade ./inode-modern-*.x86_64.rpm
sudo dnf remove inode-modern
```

升级不自动重新认证；活动服务在下一次明确重启后使用更新代码。
卸载会停止认证服务并清理本项目专属防火墙规则，因而会结束认证。
用户自行取得的原厂 generation 和钱包数据会保留，不自动删除。
详见 [安装、维护与迁移](docs/installation.md)。

## 常见问题

- **尚未配置原厂认证组件**：运行 `sudo inode-modern-setup`，或指定官方包/目录。
- **SHA256 不匹配**：不要绕过校验；重新从官方页面获取，或报告学校更新了版本。
- **导入目录不匹配**：使用原始官方包解压出的目录；不要导入运行后混入数据的目录。
- **服务不可用**：查看 `systemctl status inode-modern-backend.service`。报告问题时隐去账号、密码和地址。
- **不能安全保存密码**：检查 KDE Wallet 是否可用、已解锁；也可以不保存密码。
- **认证通过但没有地址**：检查有线连接及 NetworkManager DHCP 配置；认证和 IP 分配是不同阶段。
- **本机安装过开发版**：RPM 不覆盖 `/etc/systemd/system` 中的自定义 unit，避免意外打断连接。

## 开发与验证

见 [构建与发布](docs/building.md) 和 [安全模型](docs/security.md)。
测试中的协议、凭据和进程身份均为合成数据；构建测试不代表真实校园认证验收。

## License

inode-modern：MIT，见 [LICENSE](LICENSE)。H3C/iNode：第三方 proprietary software，
由用户从西财官方来源取得，见 [THIRD_PARTY.md](THIRD_PARTY.md)。
