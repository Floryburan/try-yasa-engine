# CTFd 全仓 UAST 与全局索引

输入仓库：`/data/fyn/yasa/YASA-Engine/CTFd`，提交 `a751d1773df7f16341801831481eeb7b1ded18c2`。

本阶段使用 **YASA 的 `--dumpAllAST` 导出接口及随仓库提供的 `uast4py-linux-amd64`**。
没有启动 CTFd、调用 LLM 或运行漏洞检测。所有索引实体均从 YASA UAST 提取；Python 标准 AST 仅用于独立验证源码定义是否遗漏。

## 结果

350 个 Python 文件全部覆盖：应用代码 185 个、测试 121 个、迁移 37 个、其他脚本 7 个。
UAST 中共有 1,748 个函数节点，其中源码函数/方法 1,716 个、lambda 20 个、解析器补充的构造函数 12 个；类 366 个。
另外提取了 3,280 条导入、21,120 个调用表达式、8,902 个赋值表达式。

## 文件

| 路径 | 内容 |
| --- | --- |
| `ast/astList.json` | YASA 导出的 AST 文件清单 |
| `ast/<hash>.json` | 每个源码文件的完整 UAST，含源位置及 YASA nodehash |
| `index/summary.json` | 版本、覆盖情况、总量和应用/测试等分组统计 |
| `index/files.jsonl` | 源文件路径、模块名、行数、源码 SHA-256 与 AST 文件映射 |
| `index/functions.jsonl` | 函数/方法/lambda、所属作用域和类、参数、装饰器、原文及位置 |
| `index/classes.jsonl` | 类、父类表达式、装饰器、原文及位置 |
| `index/imports.jsonl` | 导入模块、别名、所属作用域、匹配到的仓库文件 |
| `index/calls.jsonl` | 调用位置、callee 表达式、参数及参数引用的名字；含装饰器中的调用 |
| `index/assignments.jsonl` | 赋值位置、左右表达式，可用于查询 Blueprint/Namespace 等对象的创建 |
| `index/lookup.json` | 按函数名、类名、callee、实参名字和被导入文件反查记录 ID |
| `validation.json` | 覆盖检查、与源码独立核对、JSON 指针和作用域引用等验证结果 |
| `provenance.json` | 实际解析命令、二进制及编译文件 SHA-256 |

JSONL 每行一条记录。`file` 相对于输入仓库；`ast_file` 相对于本 README 所在目录。
`ast_path` 是该记录在 UAST JSON 内的 JSON Pointer。`scope_id` 指向其外层函数或类，模块顶层为 null。
定义的 `source` 包含完整起止行（函数/类还包含装饰器行）；lambda 的 source 因此可能包含同一行的赋值等上下文。

## 给后续模型提供上下文

建议首先筛选 `functions.jsonl` 中 `area == "application"` 的记录。
`origin == "source_definition"` 是源码中显式定义的函数/方法；`lambda` 需要保留用于回调场景；
`parser_generated` 为 UAST 补充节点，不应当作源码中真实定义的入口候选。

从一个函数出发，可以组合：

1. 自身 source、参数、装饰器及外层 scope/class。
2. 当前文件及外层作用域的 imports、assignments。
3. `lookup.calls_by_argument_name[函数名]`：该名字作为调用参数出现的位置，如 `view_func=assets_handler`。
4. `lookup.importers_by_file[文件路径]`：其他文件对该模块的导入，再结合导入别名寻找注册/调用位置。
5. `lookup.calls_by_callee[表达式]`：如 `app.register_blueprint`、`CTFd_API_v1.add_namespace`。

例子：

- `CTFd/views.py::setup` 保留 `views.route("/setup", ...)` 的装饰器证据。
- `CTFd/api/v1/challenges.py::ChallengeList` 保留 `Resource` 父类和 Namespace 路由装饰器，其方法通过 scope_id 关联。
- `CTFd/api/__init__.py` 中的 `challenges_namespace` 导入关联到 `CTFd/api/v1/challenges.py`。
- `CTFd/plugins/__init__.py` 的 `app.add_url_rule(...)` 保留 `view_func=assets_handler` 参数及嵌套函数作用域。

**当前是语法信息索引，不是完整调用图，也没有判定入口。** `calls.callee` 只是源码调用表达式，
没有自动确认其实际函数目标；名字检索可能命中其他作用域的同名符号，需结合文件、scope 和 import 核对。
仓库模块匹配也不等于符号解析成功；动态导入、重导出、实例类型和配置绑定尚需后续分析。

## 复现

从现有 UAST 重新构建索引（Python 3 标准库即可）：

```bash
cd /data/fyn/yasa/YASA-Engine
python3 tools/uast-global-index.py \
  --repo CTFd \
  --ast-dir artifacts/ctfd-uast/ast \
  --out artifacts/ctfd-uast/index
```

重新导出 UAST：

```bash
cd /data/fyn/yasa/YASA-Engine/artifacts/ctfd-uast
node /data/fyn/yasa/YASA-Engine/dist/main.js \
  --sourcePath /data/fyn/yasa/YASA-Engine/CTFd \
  --language python \
  --dumpAllAST \
  --uastSDKPath /data/fyn/yasa/YASA-Engine/my-release-bundle/uast4py-linux-amd64 \
  --report /data/fyn/yasa/YASA-Engine/artifacts/ctfd-uast/ast
```

应先确认输入仓库提交和源码哈希仍一致。导出目录包含日志：首次目录形式的 SDK 路径未解析到二进制，
第二次沙箱中的子进程报告 EPERM；随后使用完整二进制路径在授权环境重跑成功。
由于 YASA 某些解析失败路径仍返回成功退出码，索引脚本会额外核对所有 Python 文件覆盖情况，缺失时拒绝生成结果。
