# Contributing

这个项目目前以稳定自用和小范围部署为主。提交改动时请优先保持脚本可回退、配置不乱动、界面在桌面和手机端都能使用。

## 提交前检查

```bash
python -m py_compile app/app.py app/core/networks.py app/core/security.py tools/cleanup.py tools/build_release.py
python -m unittest discover -s tests -v
node --check app/static/js/app.js
```

## 改动原则

- 不随意修改会影响 WireGuard 运行的默认配置。
- 安装/卸载脚本只能清理自己创建的服务、配置、接口和规则。
- 新增 UI 需要同时考虑桌面端和手机端。
- 不提交历史发布包、缓存、日志、虚拟环境和本地备份。

## 发布

```bash
python tools/build_release.py
```

发布包生成在 `release/` 目录。历史压缩包不建议提交到源码仓库，正式分发建议使用 GitHub Releases。
