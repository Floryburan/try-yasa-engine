# django-helpdesk UAST 与索引

源仓库 `../../django-helpdesk`，commit `8c7b9ff92f018a394c6faa972e4328ad178b80b9`。

- `ast/`：YASA 导出的逐文件 UAST，172 个 Python 文件全部覆盖。
- `index/`：文件、函数、类、导入、调用和赋值 JSONL 全局索引。语法索引不是已解析完整调用图，也不等于入口判断。
- `export.log`：引擎导出日志。
- `native-verification.log`：原生解析器独立重跑，172 success / 0 failed，退出码 0。
- `provenance.json`：命令、版本、哈希和导出诊断。

引擎包装器曾输出通用解析错误，但生成结果覆盖全部文件；独立原生重跑和 Python AST 函数完整性校验均通过，没有忽略缺失文件。

源码为 src 布局，必须去掉 src 导入前缀，并显式配置应用包：

```bash
cd /data/fyn/yasa/YASA-Engine
PYTHONDONTWRITEBYTECODE=1 /data/fyn/conda_envs/laya/bin/python -B \
  tools/uast-global-index.py \
  --repo django-helpdesk \
  --ast-dir artifacts/django-helpdesk-uast/ast \
  --out artifacts/django-helpdesk-uast/index \
  --source-root src \
  --application-root src/helpdesk
```

索引 application 范围含包内 migrations。Ground truth 的 scope_partition 再将迁移与日常应用分开；不能用 CTFd 的顶层 migrations 目录假设解释本库。

完整参考标注在 [django-helpdesk-application-v1](../../LLM-check/annotations/django-helpdesk-application-v1/README.md)。没有模型 API 调用或完整污点分析。
