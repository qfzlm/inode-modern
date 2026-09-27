# 构建与发布

目标：Fedora 44 x86_64，RPM 版本 `0.2.0~beta.1`，Git tag `v0.2.0-beta.1`。
Source、SRPM、RPM 都只包含自有代码和公开 metadata，不包含原厂包。

```sh
python3 tools/release_source.py
rpmbuild -ba packaging/inode-modern.spec --define "_sourcedir $PWD/dist"
```

推荐在干净 Fedora 44 mock/chroot 或容器中构建。GUI 测试使用 offscreen Qt，
安全测试使用合成协议及隔离临时目录，不启动真实原厂认证进程。
安装/升级/卸载检查只在独立环境中做，不在正在认证的生产宿主机执行。

发布前运行 `python3 tools/public_audit.py`，检查暂存文件清单；只对该清单制作源码包。
RPM `%check` 运行公开回归测试。发行物生成后检查文件列表、摘要、权限、unit 配置和
未配置 Vendor 行为，并将实际验证范围写入 Release notes。
