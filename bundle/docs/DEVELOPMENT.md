# 开发与发布

## 源码结构

```text
app/        FastAPI 后端、模板、静态资源和核心逻辑
config/     配置样例
docs/       用户和维护文档
scripts/    安装、升级、诊断、卸载脚本
tools/      修复、清理、发布检查和打包工具
tests/      单元测试
release/    本地发布产物
```

## 本地检查

```bash
python -m py_compile app/app.py app/core/networks.py app/core/security.py tools/cleanup.py tools/build_release.py
python -m unittest discover -s tests -v
node --check app/static/js/app.js
```

如果在桌面测试环境中 FastAPI 依赖不可持久安装，至少执行以上静态检查和单元测试。正式服务器安装时会按 `app/requirements.txt` 创建 venv。

## 发布流程

1. 更新 `VERSION`。
2. 更新 `APP_VERSION`。
3. 更新 `app/templates/index.html` 中 CSS/JS 查询版本。
4. 更新 `release/manifest.json`。
5. 更新 `README.md`、`docs/` 和 `CHANGELOG.md`。
6. 运行测试。
7. 运行发布构建：

```bash
python tools/build_release.py
```

8. 检查发布包：

```bash
bash tools/release_check.sh release/wg-webui-v$(cat VERSION).tar.gz full
```

## GitHub 提交规则

不要提交以下内容：

- `release/build/`
- 历史 `release/*.tar.gz`
- `__pycache__/`
- `.pyc`
- 虚拟环境
- 本地日志、备份和临时文件

`PROJECT_CONTEXT.md` 保留为兼容文件，因为旧升级检查可能会识别它。
