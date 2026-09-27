# 第三方软件与许可边界

inode-modern 自有代码、GUI 和正式图标使用 MIT License，见 LICENSE。
本项目与西南财经大学、H3C 均无官方隶属关系。

H3C/iNode 是第三方 proprietary software，不属于 inode-modern 的 MIT 授权。
AuthenMngService、iNodeMon、iNodeClient 及其原厂库、安装包不进入本仓库、RPM、
SRPM 或 GitHub Release。本项目不授予这些文件的复制、修改或再分发权利。
用户应自行从学校官方下载页面取得并遵守原厂许可：
https://info.swufe.edu.cn/info/1027/2411.htm

setup 使用该官方页面寻找明确支持的 Linux64 E0538 附件，并在本机校验、导入。
metadata 中仅包含版本、公开文件名和 SHA256；不包含原厂 payload。
哈希表示项目核对过的字节版本，不是 H3C 的签名或安全背书。
未复制 wetype-ime-linux 或其他项目的 GPL 获取/安装代码。

Python、PySide6/Qt、systemd、nftables 等由 Fedora 软件仓库提供并遵循各自许可，
不是本项目重新授权的代码。
