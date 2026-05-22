#!/usr/bin/env python3
"""兼容旧升级脚本的 AllowedIPs 同步入口。

旧版网页升级流程可能会检查或调用 sync_allowedips.py。
实际逻辑统一转发到 repair_allowedips.py，避免两套同步逻辑不一致。
"""
from pathlib import Path
import runpy
import sys

here = Path(__file__).resolve().parent
repair = here / "repair_allowedips.py"
if not repair.exists():
    raise SystemExit(f"未找到修复工具：{repair}")

sys.argv[0] = str(repair)
runpy.run_path(str(repair), run_name="__main__")
