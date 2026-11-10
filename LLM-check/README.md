# 用模型逐函数判断 Python 入口

文件和实验目录的用途见 [目录说明](目录说明.md)。

读取 YASA 导出的 UAST 全局索引，为每个函数整理上下文，再发起一次模型 API 请求。
入口判断由模型完成；这里不调用 YASA 原有框架入口 Checker，也不根据路由函数名直接给出判断。

## 运行环境与输入

Python 3.7+ 标准库即可。输入是 `tools/uast-global-index.py` 生成的索引及其原始 AST：

```text
artifacts/ctfd-uast/
├── ast/          # YASA 的逐文件 UAST
└── index/        # files/functions/classes/imports/calls/assignments.jsonl
```

默认处理 CTFd 应用代码中全部 **847 个源码函数/方法**，包含普通工具函数，不使用入口候选预过滤。
默认排除测试、迁移及解析器生成的函数；`--include-lambdas` 加入 14 个应用 lambda。
`--area all` 可处理仓库全部源码函数。输入源码的 SHA-256 会与索引核对，变化后需重新导出 UAST/索引。

## 1. 提取逐函数上下文，不联网

在 `YASA-Engine` 目录运行：

```bash
python3 LLM-check/entrypoint_check.py prepare
```

输出 `LLM-check/runs/ctfd/contexts.jsonl` 和 `manifest.json`。
每行一个函数上下文，包含：

- `target`：目标函数原文、位置、参数、装饰器、所属类与 UAST 定位。
- `nodes`：关联函数、类、导入、赋值、调用、形参等证据。
- `edges`：词法/导入可关联的调用、调用者、被调用者、装饰器、继承、注册实参/接收者、对象初始化和参数传递关系。
- `unresolved`：未解析的调用目标、外部基类等。
- `coverage`：深度、节点数、字符预算、被省略的记录和源码截断情况。

只准备几个特定函数：

```bash
python3 LLM-check/entrypoint_check.py prepare \
  --function CTFd.views.setup \
  --function CTFd.api.v1.challenges.ChallengeList.get \
  --function CTFd.plugins.register_plugin_assets_directory.assets_handler \
  --out LLM-check/runs/ctfd-smoke
```

默认最大 10 跳、100 个节点、60,000 字符。函数本体尽量完整保留，最多占上下文预算的一半；
其他函数源码默认最多 6,000 字符，类源码最多 1,400 字符，同时保留父类、装饰器及方法列表。
注册、继承及对象传递链路优先于大量内部调用；应用入口的上下文不引入来自测试/迁移的反向调用。
如果需要更广的上下文：

```bash
python3 LLM-check/entrypoint_check.py prepare \
  --max-depth 14 --max-nodes 180 --max-context-chars 120000 --source-chars 12000
```

字符数是序列化 JSON 的字符数，**不是模型 token 数**；需与所用模型的上下文窗口匹配。

## 2. 预览逐函数模型请求，不联网

```bash
python3 LLM-check/entrypoint_check.py run \
  --contexts LLM-check/runs/ctfd/contexts.jsonl \
  --out LLM-check/runs/ctfd/requests-preview.jsonl \
  --dry-run --limit 3
```

无需 API 密钥。输出包含实际 system/user messages 和生成参数，方便先检查模型会看到什么。
预览状态是 `dry_run`，不会冒充模型判断结果，也不会覆盖已有的真实判断结果文件。

## 3. 配置并调用模型 API

接口采用兼容 Chat Completions 的 JSON HTTP 请求。复制 `config.example.json` 为 `config.json`，
填写实际 `api_url`（完整 `/chat/completions` 地址）和 `model`。
密钥只从配置指定的环境变量读取，默认 `LLM_API_KEY`，不要写入配置文件或提交到 Git。
`LLM_API_URL` / `LLM_MODEL` 环境变量优先于配置。示例配置里的地址和模型名需要替换。
本地无鉴权服务可将 `require_api_key` 设为 false；不支持 JSON 模式的服务可将 `json_mode` 设为 false。

先对三个函数试运行：

```bash
python3 LLM-check/entrypoint_check.py run \
  --contexts LLM-check/runs/ctfd/contexts.jsonl \
  --config LLM-check/config.json \
  --out LLM-check/runs/ctfd/predictions.jsonl \
  --workers 2 --limit 3
```

确认配置后去掉 `--limit 3`，会逐函数处理全部上下文。也可重复使用 `--function` 指定确切函数名/全限定名/ID。
每个函数独立请求；默认最多 2 个并发请求。结果逐条追加并刷新，适合中断后继续运行。

## 模型输出与校验

```json
{
  "is_entrypoint": true,
  "entrypoint_kinds": ["http"],
  "formation_types": ["decorator", "registration"],
  "confidence": 0.9,
  "reason": "目标函数通过 Blueprint 路由注册，Blueprint 又被注册到应用。",
  "evidence": [
    {"record_id": "上下文中实际存在的记录ID", "explanation": "对应的注册证据"}
  ],
  "missing_information": []
}
```

示例仅说明格式，不是实际模型结果。

- `is_entrypoint` 支持 true / false / null；null 表示证据不足。
- `entrypoint_kinds`：http、rpc、cli、event、lifecycle、other。
- `formation_types`：decorator、registration、inheritance、interface_implementation、configuration、callback、other，允许多选。
- 只接受上下文中存在的证据 ID；正判断必须有类型、形成方式和证据。
- 接口错误、非正常结束、非法 JSON、缺字段、伪造证据 ID 都记录为 `status=error`，不会当成“非入口”。
- 检查证据 ID 存在只能保证引用可追溯，不能代替人工验证模型推理是否正确。

`predictions.jsonl` 保存函数身份、判断、模型原始回复、用量、请求指纹和上下文覆盖情况；
`predictions.summary.json` 保存本次运行统计。不会写出 Authorization header 或密钥。

相同函数、上下文、提示词、模型、地址及生成参数的成功结果会自动复用。修改模型或上下文后自动重跑；
错误结果不缓存，重新运行会重试。中断产生的最后一条不完整 JSON 会另存为 `.incomplete-tail` 后移除以便续写。
`--no-resume` 可强制追加新的判断。429、部分 5xx、网络超时及非法模型回复按 `retries` 重试，默认 2 次。

## “上下完整链路”的边界

当前实现恢复可从 UAST/索引关联的静态证据链，**不承诺完整运行时调用图**。

- 基于文件、作用域、导入及别名匹配，不进行全仓同名函数猜测。
- 调用者/被调用者关系、闭包外层作用域和注册辅助函数的参数关联均可进入上下文。
- 普通内部回调不自动视作外部入口，参数引用关系也不等于已证明框架注册。
- 动态导入、实例属性指向、反射、复杂配置、框架生成方法及任意闭包数据流可能无法解析。
- 同作用域多次赋值和多目标关联标为 candidate；不把它们宣称为确定运行时关系。
- 上下文预算不足会显式记录；模型应在关键注册证据缺失时输出 null。

当前结果是模型判断清单，还没有绑定为 `analyzer.entryPoints` 内的 YASA 运行时对象。

## Laya：先测试四个已讨论的 CTFd 样例

`laya_smoke.py` 使用 Laya 的 `/v1/systemone` 接口，与上面的 Chat Completions 客户端分别运行。
Laya 使用 `state`（源码和静态关系）以及 `questions`（判断说明、候选项定义），返回类别和概率；
不要求它生成推理过程或自由文本 JSON。实际服务检查为 `http://127.0.0.1:8001/health`。

提示词在 `prompts/entrypoint_laya_v1.json`，包括入口 yes/no/unknown、七个可重叠的形成方式问题，
以及一个主要触发场景问题。注册 API、继承框架处理方法、明确接口契约、配置绑定、框架回调、
入口装饰器和其他机制分别定义。鉴权装饰器、普通继承、普通内部回调不自动视为入口。

`experiments/ctfd_four_cases.json` 选取：`CTFd.views.notifications`、
`CTFd.api.v1.challenges.ChallengeList.get`、
`CTFd.plugins.register_plugin_assets_directory.assets_handler`、
`CTFd.utils.initialization.init_request_processors.needs_setup`。
这是人工选取证据的四例试跑，检验模型与提示词，不代表全仓自动上下文提取效果或分类准确率。
接口实现、配置绑定暂时只有问题定义，没有对应的已知正样例。

在 `YASA-Engine` 目录运行：

```bash
# 需要安装好 Laya 和 Transformers 的环境；只加载本地 tokenizer，不加载模型权重。
PYTHONDONTWRITEBYTECODE=1 USE_TF=0 USE_TORCH=1 \
  /data/fyn/conda_envs/laya/bin/python LLM-check/laya_smoke.py prepare

# 实际发送四次请求；无鉴权的本地服务不需要 API key。
# 若服务有鉴权，从 LAYA_API_KEY 环境变量读取，不写进实验记录。
PYTHONDONTWRITEBYTECODE=1 \
  /data/fyn/conda_envs/repograph-vllm/bin/python LLM-check/laya_smoke.py run
```

`prepare` 保留完整目标源码，选取已有 UAST 记录及补充的注册链记录；不添加人工推断的调用边。
辅助定义最多保留 1,600 字符，类定义最多 400 字符，省略量明确标注。
源码使用保留换行的文本，记录用短 ID 表示；`prepared.json` 保存短 ID 与原 UAST ID 的映射。
设置 `max_len=8192`、`head_max_len=512`，逐问题核对实际 token 数和选项区分情况；
发现输入会被模型截断时中止，避免把缺少证据的结果当成正常实验。

输出在 `runs/laya-four-v1/`：`requests/` 为完整实际请求，`contexts/` 为选取的结构化证据，
`responses/` 为原始模型回复，`results.json` 与 `RESULTS.md` 为整理结果。
人工预期单独保存，**不发送给模型**。`status=success` 仅表示请求和响应格式有效，不代表判断正确。
独立分类若出现矛盾，会原样保留并记录 `consistency_issues`，不替模型改答案。
入口判定为 no/unknown 时，最终分类留空，原始各项选择仍保留在 `raw_formation_choices`。

`run` 会重新请求四个样例；只重新整理已有回复而不调用模型时：

```bash
python3 LLM-check/laya_smoke.py summarize
```

2026-10-26 的首轮四例结果出现大量过选，原始请求保存在 `runs/laya-four-v1/`，未覆盖重跑。
随后对同一个 `notifications` 做了提问对照：中英文、yes/no 与 A/B/C 标签、选项顺序、
布尔问题、完整上下文与仅目标源码。见 `runs/laya-prompt-diagnostic-v1/RESULTS.md`。
同一英文继承问题只更改选项键，在完整上下文下从错误 yes 的 0.8983 变成接近均匀的分布；
仅目标源码与 A/B/C 组合才选对，正确项概率 0.404。该对照说明写法及上下文敏感，尚不能证明某个新模板可靠。

首轮压缩器省略了导入的 module/imported_name/local_name，仅留下 UAST 的短 source 名字；
已修复后续输入的导入绑定输出。没有覆盖首轮记录，也没有把修复后的版本冒充已完成评测。
需要重跑时使用新的输出目录，例如 `--out LLM-check/runs/laya-four-v2`。

准备提问对照文件（不会发请求），或整理已经保存的回复：

```bash
python3 LLM-check/laya_prompt_diagnostic.py prepare
python3 LLM-check/laya_prompt_diagnostic.py summarize
```

## 保持标签的正负样本对照实验

`experiments/ctfd_balanced_dev_v1.json` 固定 4 个正样本和 4 个负样本及其人工复核说明。
负样本为 `hexencode`、`safe_format`、`markup` 和 `register_plugin_assets_directory`。
后两者用于检查“被入口调用”和“注册另一个处理函数”是否被错误当成目标自身的入口绑定。
这是一组人工选取的开发样本，不是独立测试集或全仓 ground truth。

`laya_evaluate.py` 比较原始提示词与 `prompts/entrypoint_laya_v2.json`：

- `is_entrypoint` 的 `yes/no/unknown`、七个形成方式问题、场景候选标签和候选顺序完全保持不变。
- 两版使用完全相同的源码、UAST 静态关系、导入绑定和目标词法归属；只改变任务说明、问题及类别说明。
- 第二版使用明确的目标归属说明与通用正负对照例子；例子不使用本次样本的函数或人工预期。
- 两版共用两阶段流程：模型先判断入口，回答 yes 后才分类；每次默认发一个问题，减少 GPU 峰值显存。
- 原始类别直接记录，不使用阈值、规则修正或人工标签覆盖预测。非入口时分类未执行，保留该状态。
- 输入长度逐问题核对，服务端截断也会作为错误；unknown、错误与真负例分别计数。

在 `YASA-Engine` 目录运行：

```bash
PYTHONDONTWRITEBYTECODE=1 USE_TF=0 USE_TORCH=1 \
  /data/fyn/conda_envs/laya/bin/python LLM-check/laya_evaluate.py prepare

PYTHONDONTWRITEBYTECODE=1 \
  /data/fyn/conda_envs/repograph-vllm/bin/python LLM-check/laya_evaluate.py run

# 只整理结果，不调用模型
python3 LLM-check/laya_evaluate.py summarize
```

默认输出 `runs/laya-balanced-dev-v1/`：`manifest.json` 冻结样本、提示词和输入索引指纹；
`prepared.json` 保存输入长度审计及请求指纹；`contexts/` 保存选取的证据及短 ID 映射。
每版目录的 `requests/` 与 `responses/` 是两阶段真实请求与原始回复，`request-plans/` 是完整问题计划。
`results.json`、`metrics.json` 和 `RESULTS.md` 保存逐函数结果、混淆矩阵和类别匹配统计。
人工预期仅在清单、prepared/results 的独立字段中保存，不出现在实际请求中。

`prepare` 不会覆盖已经准备的实验；修改提示词后指定新的 `--out`，`prepare` 和 `run` 使用相同目录。
`run` 在同一冻结实验中复用请求指纹相同的成功记录。需要比较新流程时使用新目录，并记录修改内容。

2026-10-26 本轮结果：baseline 与 optimized 均为 TP=4、TN=0、FP=4、FN=0，入口精确率 0.5；
4 个负样本全部误报，4 个正样本的形成方式完全匹配数为 0。两版对所有样本都选择七种形成方式。
全部请求成功且未截断，说明这版改动没有改善过选；这些数字只描述这 8 个开发样本。
接口实现、配置绑定仍没有正样本。与历史四例实验相比流程和证据也变了，不把差异归因于提示词。

## 对照加入 YASA 全库调用图

`tools/export-full-callgraph.py` 调用当前引擎的 `--checkerIds callgraph --dumpAllCG --dumpEntrypoint`。
只有调用图 checker 被启用，`dumpEntrypoint` 用来跳过后续污点入口执行；不将 `entrypoints.json` 发给模型。
2026-10-26 对整库（包含测试、迁移）导出 8,356 个节点、20,417 条边，耗时约 29 秒，
文件为 `artifacts/ctfd-full-callgraph-20261026/report/callgraph.json`。

`laya_callgraph_compare.py` 冻结上一轮第二版提示词、同一批 4 正 4 负样本和两阶段流程，
比较 `uast_only` 与 `uast_plus_yasa_cg`。后者仅在原输入末尾追加真实 YASA 图的目标邻域。
匹配只按源码文件和定义行，8 个目标各匹配一个节点；不使用函数短名称猜测。
完整调用图保留在磁盘，模型输入最多 2 跳、24 条边，超预算会缩小图视图，保留完整目标源码；
`callgraph-coverage.json` 记录目标入度/出度及省略的直接边，原始局部图在 `callgraph-views/`。
外部共享节点保留直接边但不继续扩展，避免把其他处理函数通过库函数 hub 混入上下文。

引擎图仍是静态符号解释结果，包含库函数/回调近似。例如图中有 `add_url_rule -> assets_handler`，
也有 `functools.wraps -> ChallengeList.get`；这些边不都代表真实运行时直接调用。
YASA 图本身同样由 UAST 构建，所以这个实验不能独立判断底层解析器是否正确。

在 `YASA-Engine` 目录运行：

```bash
# 首次生成；已有目录会拒绝覆盖，重新导出时用新的 --out。
python3 tools/export-full-callgraph.py

PYTHONDONTWRITEBYTECODE=1 USE_TF=0 USE_TORCH=1 \
  /data/fyn/conda_envs/laya/bin/python LLM-check/laya_callgraph_compare.py

PYTHONDONTWRITEBYTECODE=1 \
  /data/fyn/conda_envs/repograph-vllm/bin/python LLM-check/laya_evaluate.py run \
  --out LLM-check/runs/laya-yasa-callgraph-v1
```

默认输出 `runs/laya-yasa-callgraph-v1/`，保留原始请求、回复、置信度字段、图指纹和覆盖信息。
实际对照结果两组仍均为 TP=4、TN=0、FP=4、FN=0，正样本形成方式完全匹配 0/4，
各样本依然七类全选。全部请求未截断，最大序列 7,510 token。
本轮增加图证据没有改善识别；这是有预算的邻域输入对照，不是把完整 17 MB 图直接塞入模型。

## Jev API 密钥与同样本实验

本机密钥填写位置是 `LLM-check/.env`，变量名沿用官方 SDK：

```dotenv
TYPESAFE_API_KEY=填入你的真实密钥
TYPESAFE_BASE_URL=https://api.typesafe.ai
TYPESAFE_DEFAULT_MODEL=jev-latest
```

`.env` 已加入 Git 忽略；新建文件权限为 0600。可从 `.env.example` 复制模板，保留已有密钥文件。
`jev_config.py` 读取此文件，环境变量中的非空值优先；不执行文件里的 shell 命令。
`check-config` 只显示是否配置密钥，不显示密钥内容，也不联网。

在 `YASA-Engine` 目录运行：

```bash
python3 LLM-check/jev_evaluate.py check-config

# 离线准备，沿用冻结的八个样本、第二版提示词和 YASA 调用图输入。
python3 LLM-check/jev_evaluate.py prepare

# 实际请求官方 Jev API，会消耗账户额度；此前两个命令不会发送请求。
python3 LLM-check/jev_evaluate.py run
```

默认输出 `runs/jev-ctfd-smoke-v1/`，复用模型判断与计分流程、原始标签及源码证据。
只发送 Jev 支持的 `model/state/questions`，移除 Laya 的 `max_len/head_max_len`，不请求本地 `/health`。
密钥仅用在 Authorization header，不写入 prepared/manifest/请求体/实验结果。
离线准备时不要求密钥；实际请求前检查密钥与冻结的 API 地址、模型是否一致。
Jev 使用自己的分词器，未将 Laya 的 token 计数冒充 Jev 长度验证。

官方参考：<https://docs.typesafe.ai/introduction/quickstart>、<https://docs.typesafe.ai/api/system-one>。

## 精简源码输入与真实长度审计

`compact_context.py` 保留目标函数全文、最多六个直接使用位置，以及必要的外层头部/依赖语句和导入绑定。
内部用 UAST 关联定位，发给模型的文本不包含图边；同一源码行只出现一次，外层实现不会再重复内层目标。
长 import 语句只投影保留实际使用的别名，原始 import 在 contexts/ 的 sidecar 中保留。
`prompts/entrypoint_compact_v1.json` 去掉长规则和示例，保留全部问题 ID、类别标签和选项顺序。
直接使用位置超过预算时记录候选数、保留数和省略数；不会裁剪目标函数。

```bash
# 在 YASA-Engine 目录；只离线准备，不调用 API。
PYTHONDONTWRITEBYTECODE=1 USE_TF=0 USE_TORCH=1 \
  /data/fyn/conda_envs/laya/bin/python LLM-check/compact_prepare.py \
  --out LLM-check/runs/jev-compact-v2

# 实际调用（会使用 Jev 账户额度）。
python3 LLM-check/jev_evaluate.py run --out LLM-check/runs/jev-compact-v2
```

`state-text/` 是模型看到的完整 state 文本，`input-preparation-audit.json` 保存精简前后字符数和保留范围。
`prepared.json` 的本地精确 token 计数明确标为 laya-multilingual 参考值，不冒充 Jev 计数。
Laya 审计同时检查 state、问题说明与每个选项的实际编码和丢弃量，不能只看 max_len。
Jev 的实际输入数从真实回复 `usage.input_tokens` 记录；实际发出的 UTF-8 请求保存在 wire-requests/，
对应字节数和 SHA-256 保存到各 stage 的 input_audit，方便核对客户端没有偷偷裁剪文本。
服务端缺少明确截断字段时状态为 `not_reported`，不是 `reported_no_truncation`。
`actual-input-audit.json` 汇总服务端计数、截断遥测与请求错误。

2026-10-26 本机实际请求该精简版时，Jev 返回 HTTP 451：`Typesafe is not available in your region.`。
没有取得模型回复和 usage，因此真实 Jev token 数、截断情况、分类效果均未核实；错误不会计为负预测。
后续遇到 401/402/403/451 会提前停止剩余请求。历史失败回复保留，不尝试绕过服务限制。

后续排查确认：当时脚本对 Jev 禁用了环境代理，导致连接方式与终端 curl 不同。
现已修正：Jev 遵循终端代理设置，本地 Laya 保持直连；同一份精简输入已成功取得 Jev 回复。
因此上述 451 描述是历史失败记录，不代表当前环境的服务状态。

同一份精简文本也已送往本地 Laya，输出在 `runs/laya-compact-v1/`：

```bash
PYTHONDONTWRITEBYTECODE=1 USE_TF=0 USE_TORCH=1 \
  /data/fyn/conda_envs/laya/bin/python LLM-check/compact_prepare.py \
  --provider laya --out LLM-check/runs/laya-compact-v1

python3 LLM-check/laya_evaluate.py run --out LLM-check/runs/laya-compact-v1
```

8 个样本完成 64 次实际请求。每次本地精确分词计数都与服务端 usage 一致，实际输入 272–4,590 token，
64 条回复均报告 truncated=false、state_tokens_dropped=0，本地问题说明和选项也没有 token 丢弃。
模型判对 4 个正例和 1 个负例（safe_format）；另外 3 个负例误报，七类全选仍存在。
相对历史复杂输入仅改善了一个负例；这轮输入与提示说明共同精简，不能分离两者的贡献。
逐请求核对结果见 `verification.json`，分类和计数分别见 `RESULTS.md`、`actual-input-audit.json`。

## 全仓库逐函数 Jev 扫描

`jev_scan.py` 自动枚举 UAST 索引中的普通函数、方法和嵌套函数，不再依赖八个开发样本、
人工 supplement 或历史实验文件，也不需要 Laya 模型或 tokenizer。
沿用精简提示词、问题 ID、全部输出标签和多标签语义，不通过框架规则预先排除函数。
先判断是否为入口，仅当模型回答 yes 后请求形成方式和用途；unknown 不当成 no。

在 `LLM-check` 目录，统一使用 laya 环境的 Python：

```bash
# 离线生成全部业务函数的输入；当前 CTFd 为 847 个。
/data/fyn/conda_envs/laya/bin/python jev_scan.py prepare \
  --area application --out runs/jev-ctfd-application-v1

# 实际请求 Jev；重复执行同一目录可续跑。
/data/fyn/conda_envs/laya/bin/python jev_scan.py run \
  --out runs/jev-ctfd-application-v1

# 单独重新汇总（run 也会生成汇总）。
/data/fyn/conda_envs/laya/bin/python jev_scan.py summarize \
  --out runs/jev-ctfd-application-v1
```

字面意义的全仓库：prepare 时改用 `--area all` 和新的输出目录，当前为 1,716 个函数，
包含测试、迁移和脚本。其他区域可选 `tests/migrations/scripts_or_other`。
默认排除 lambda（20 个）和解析器生成函数（12 个）；不判断模块顶层执行入口。
`--index` 指向其他仓库的 UAST 索引，`--repo` 可覆盖搬迁后的源码位置；源码哈希必须与索引一致。
`--function` 可重复指定函数 ID/名称/全限定名，`--limit 20` 可生成独立的小批量试跑目录。

prepare 只构造输入，不调用 API；提取失败函数保存在 `preparation-errors.json`，不是负预测。
默认 `--question-batch-size 1` 与八例实验一致：N 个函数中 P 个预测为入口时，共 N+8P 次成功请求。
可在新的 prepare 运行中指定 `--question-batch-size 8`，一次提交同一函数的八个分类问题，降为 N+P；
标签不变，但批量提问可能影响模型结果，应作为新的实验配置比较。
每次请求仍只包含一个目标函数，完整目标体不裁剪；直接引用默认最多六处并记录省略数量。
Jev 输入超限或调用失败时明确记录错误，不自动截断函数或伪造负标签。

输出包括 `entrypoints.json`、`scan-summary.json`、`RESULTS.md`、`review-needed.json`、
逐函数 `contexts/` 和 `state-text/`，以及原始请求、实际 wire bytes、回复与 usage 审计。
断点续跑跳过成功函数，并复用请求及回复哈希匹配的成功阶段，避免分类中断后重发入口判断。
没有全仓人工真值，因此汇总只报告发现数量、未知、失败和未执行数量，不报告准确率。
精简上下文使用静态关联，不能保证包含动态注册、反射或外部配置的全部运行时链路。

### 函数定义去重与接收对象绑定证据

`function_identity.py` 按文件、全限定名/作用域、起止行列和定义来源合并同一定义的多条标识，
保留 `definition_alias_ids`；函数正文冲突时显式报错。同名的 getter/setter、不同作用域和不同文件的
函数不会仅凭名称或相同代码合并。去重发生在 limit 之前，按任一别名 ID 查找也会保留全部别名。
扫描 case_id 从定义身份生成，不依赖运行时 qid、克隆编号或对象地址。

`binding_context.py` 对类方法沿仓库内可解析的继承关系收集接收类候选；显式重写/遮蔽该方法的分支
不作为继承原方法的候选。保留类头部、装饰器、类作为参数/容器值/别名的使用位置，以及实例构造、
实例别名和绑定方法引用。方法实际读取的接收对象属性会补充对应类字段及实例赋值，
而与目标方法无关的兄弟方法调用尽量不引入。以上均是通用语法证据，不运行框架入口识别 checker。

一个定义仍只提交为一个目标函数，不同接收类/实例/注册场景在同一上下文中保留为不同证据。
所有新增源码继续按文件、行号去重，保留完整目标函数，输出标签和判定流程不变。
默认最多 12 个接收类、24 条绑定证据，分别可用 `--max-binding-classes` 和 `--max-binding-sites` 设置；
多类的证据轮流选取，避免第一个类占满全部预算，省略数量在 state 与 coverage 中明确保存。
直接使用位置仍由 `--max-uses` 控制。局部绑定依赖还限制为每作用域八条、每条少于六十行，超出会记录省略。
继承候选不证明 Python MRO 或运行时调度；动态工厂、外部依赖和动态修改仍可能无法完整解析。

当前业务范围的新输入目录为 `runs/jev-ctfd-application-bindings-v3`，与旧结果分开保存：

```bash
# 输入已准备时，直接运行。此命令会调用 Jev。
/data/fyn/conda_envs/laya/bin/python jev_scan.py run \
  --out runs/jev-ctfd-application-bindings-v3 --timeout 180

# 从头准备另一个实验时，使用新目录；这一步不调用 API。
/data/fyn/conda_envs/laya/bin/python jev_scan.py prepare --area application \
  --out runs/jev-ctfd-application-bindings-custom --max-binding-classes 12 --max-binding-sites 24
```

run 每处理十个新函数输出一条 `[JEV]` 进度，结束时输出对齐统计表：范围内文件数、物理源码行数、
函数完成情况、入口数量、耗时、请求数、输入/输出/总 token，以及 API 请求延迟均值和 70%/99%/100% 分位。
物理行数包含空行和注释；业务模式只计业务文件，不混入测试和迁移。
`last invocation` 统计最近一次 run 的真实请求，缓存复用不增加请求数和用量。
`Saved ... tokens` 是当前保存回复的用量合计，不代表所有历史重试消耗或账户账单。
缺少 usage 字段会标记 partial，不会把缺失量解释成零消耗；未提供费用字段时不推算金额。
每次真实尝试的用量、HTTP 状态和耗时写入 `usage-events/<invocation_id>.jsonl`，
运行信息保存到 `invocations/`，汇总另存 `terminal-statistics.json` 并嵌入 `scan-summary.json` 和 `RESULTS.md`。
Ctrl+C 时保存已有结果并输出统计。旧结果可通过 summarize 查看用量；旧版本没有记录的总耗时显示 not recorded。

```bash
/data/fyn/conda_envs/laya/bin/python jev_scan.py summarize \
  --out runs/jev-ctfd-application-v1
```

## django-helpdesk 参考标注

新增 [django-helpdesk ground truth](annotations/django-helpdesk-application-v1/README.md)：
按 `pyproject.toml` 的 `src/helpdesk` 安装包范围覆盖 425 个源码函数，203 个入口、218 个非入口、4 个不确定。
其中日常应用代码 409 个（190/215/4），迁移 16 个（13/3/0）；测试、示例和部署脚本单列范围，不纳入本次目标。
JSON/JSONL/CSV 保存同一套函数身份、分类、完整源码证据和绑定位置，字段口径沿用 CTFd。
这是 AI 辅助静态参考，无独立人工复核，没有读取预测或调用 Jev；入口包含 HTTP 与框架回调，不能把函数数量当作 URL 数量。

源码采用 `src` 布局，UAST 索引已使用 `--source-root src --application-root src/helpdesk` 构建，
位于 `../artifacts/django-helpdesk-uast/index`。重建标注运行 `build_helpdesk_reference.py`，详细命令、分类统计和边界见上述 README。

## 验证

### Jev 入口之后的 source 试验

全业务入口扫描可以直接读取已有 Jev 入口扫描结果，无需先准备 Laya 小样：

```bash
PYTHONDONTWRITEBYTECODE=1 /data/fyn/conda_envs/laya/bin/python -B jev_sources.py prepare \
  --jev-run runs/jev-ctfd-application-bindings-v3 \
  --out runs/jev-sources-custom-all-v1 --max-helpers 2 --batch-size 8 --max-state-chars 24000

PYTHONDONTWRITEBYTECODE=1 /data/fyn/conda_envs/laya/bin/python -B jev_sources.py run \
  --out runs/jev-sources-custom-all-v1 --workers 4 --retries 2 --timeout 180

/data/fyn/conda_envs/laya/bin/python -B jev_sources.py summarize --out runs/jev-sources-custom-all-v1
```

CTFd 这轮全量输入位于 `runs/jev-sources-ctfd-application-v1`：
此前业务范围 847 个函数中模型选出的 256 个入口、7,048 个候选配对、1,010 批请求。
该范围有 185 个 Python 文件，62 个文件包含预测入口；并不表示逐函数扫描了所有非入口和测试代码。
入口函数本体的 5,486 个候选全部纳入；另有一层本地辅助实现提供 1,562 个候选配对。
形成方式和 source 问题保持小样口径，但每批只列当前候选，取消候选数量上限。

每批完整保留目标函数和候选所在函数，超出字符预算时只移除可选证据。
字符预算不是 Jev 的 token 限制；目标和候选函数本体过长时保留全文并标记 oversized，服务错误明确保存。
辅助函数数量、长度、静态引用和调用深度仍有预算，`contexts/` 与 manifest 的 cases 逐项记录信息缺口。
没有源码位置的 UAST 辅助赋值标为 unresolved，不中断其他函数，也不当作非 source。

run 支持有限并发、网络/临时 HTTP 错误重试、每批保存及断点续跑。
`usage-events/` 记录每次真实请求（含重试），`invocations/` 记录各次运行耗时与复用数。
`entrypoint-status.json` 记录每个入口完成情况；`unique-sources.json` 按源码位置合并模型选 yes 的候选，
保留各入口下的原始判断、概率和冲突，不投票改标签。
统计中的 possible_sources 是入口与候选的配对数，unique_source_positions 是不同源码位置数。

用相同输入切换到 Jev API：`jev_sources.py` 复用冻结的源码上下文、候选、问题与选项顺序，
只修改模型和服务地址，移除 Laya 专用长度参数。读取本目录已有 `.env` 的 `TYPESAFE_API_KEY`，不在结果中保存密钥。

```bash
PYTHONDONTWRITEBYTECODE=1 /data/fyn/conda_envs/laya/bin/python -B jev_sources.py prepare \
  --source-run runs/laya-sources-ctfd-pilot-v2 --out runs/jev-sources-custom-v1

PYTHONDONTWRITEBYTECODE=1 /data/fyn/conda_envs/laya/bin/python -B jev_sources.py run \
  --out runs/jev-sources-custom-v1 --timeout 180

/data/fyn/conda_envs/laya/bin/python -B jev_sources.py summarize --out runs/jev-sources-custom-v1
```

本轮实际输出位于 `runs/jev-sources-ctfd-pilot-v1`。`input-equivalence.json` 记录输入一致性核对，
`possible-sources.json` 保存模型选 yes 的候选；`candidate-results.csv`/JSON 保存全部判断、概率和服务原始 confidence。
Jev 的 confidence 保留原值，不能按 Laya 的归一化熵定义解释，也不能当作本任务准确率。
`summary.json` 统计响应中保存的 token 用量；缺失 usage 的回复单列，不等于账户历史计费。
沿用的 Laya 分词审计只供参考，不作为 Jev 的实际分词数；Jev 未报告截断时也不能声称服务端已验证未截断。
相同 run 命令可以续跑，并复用请求和原始回复哈希一致的成功记录。

本次 Laya source 试验的回复、派生报告与诊断输出已按要求删除，冻结输入仍保留，便于复现这次服务切换。

#### 输入构建与本地 Laya 调试

`laya_sources.py` 读取已有 Jev 的 `manifest.json`、`prepared.json`、`results.json`，
只选择模型判断为入口的函数，不重新调用 Jev，不修改入口标签或 YASA 引擎。
当前只支持 Python。默认选 8 个样例以覆盖预测的形成方式和用途，也可以重复传入 `--function`。
样例选择与输入构建均不读取 ground truth 或已有漏洞报告。

先保留已有精简上下文的完整目标、直接使用位置、外层实现、接收对象和导入。
注册/回调补充本地注册器实现；装饰器补充本地装饰器实现；继承/接口补充本地基类、同名方法和初始化；
配置补充目标引用的赋值与绑定。所有入口都额外查找一层可静态解析的本地被调用函数。
多标签执行各类取证的并集，按文件和源码行去重；预测标签错误或未解析的依赖会保留记录。
不会读取整个依赖库或搜索所有外部配置文件，也不宣称构建了完整运行时链路。

候选位置包括函数参数、调用返回值、属性读取、下标读取；嵌套函数单独看待。
这些位置只是待判断候选，不能通过 API 名称直接标成 source。
Laya 对候选逐项回答 yes/no/unknown，JSON 列表由客户端组装。
source 在这轮定义为外部可控输入进入应用的起点，普通传播、内部常量、配置和数据库读取不会预先算作 source。
因此这轮与 YASA 的较宽 source 规则口径不同，不能把漏洞报告的 source 直接当作完整真值。

在本目录执行，服务接口为 `http://127.0.0.1:8001/v1/systemone`：

```bash
run_dir="runs/laya-sources-custom-$(date +%Y%m%d-%H%M%S)"

PYTHONDONTWRITEBYTECODE=1 USE_TF=0 USE_TORCH=1 \
  /data/fyn/conda_envs/laya/bin/python -B laya_sources.py prepare \
  --jev-run runs/jev-ctfd-application-bindings-v3 \
  --out "$run_dir" --limit 8 --max-len 3072 --batch-size 4 \
  --max-helpers 2 --max-candidates 32

PYTHONDONTWRITEBYTECODE=1 USE_TF=0 USE_TORCH=1 \
  /data/fyn/conda_envs/laya/bin/python -B laya_sources.py run \
  --out "$run_dir" --timeout 180

/data/fyn/conda_envs/laya/bin/python -B laya_sources.py summarize --out "$run_dir"
```

prepare 使用本地 Laya tokenizer 检查真实序列长度，保留目标全文，预算不足时删除可选证据并记录遗漏。
辅助函数不完整时，其候选不会继续发送；完整目标仍过长则报准备错误。
这些数量/长度预算会导致覆盖缺口，不能把未判断位置当作没有 source。
run 可用同一命令续跑：仅复用请求哈希和原始回复哈希匹配的成功结果。
GPU 显存不足时 Laya 服务可能自行回退 CPU，客户端的 `--max-len` 和 `--batch-size` 都可以降低单次开销。

输出：`RESULTS.md` 阅读版，`possible-sources.json` 模型选 yes 的候选，
`candidate-results.json` 全部已判断候选（含 no/unknown），`contexts/` 全部证据和遗漏，
`requests/` 实际请求内容，`responses/` 服务原始回复。
每条记录的 `source_probability` 是 P(yes)，`model_confidence` 是服务返回的归一化熵置信度，
`x_jev_confidence` 是另一种服务端计算值。均保留原值，不代表已验证的正确率。

### 将 Jev 入口、source 和 sink 接入 YASA

`export_yasa_inputs.py` 将已保存的 Jev 入口、source 和 sink 扫描结果导出为
`yasa-llm-input/v2` JSON，不调用 API，不读取参考标注，不按概率阈值更改模型答案。
入口只取成功且 `is_entrypoint=true` 的定义；source 只取成功且原始 `choice=yes` 的位置。
sink 只取成功且原始 `is_sink=true` 的调用位置，保留原始分类、置信度及危险参数选择。
`--sink-links` 可指定已生成的反查目录，进一步选择其中的 sink 和去重候选入口。
未完成、失败、输入哈希不一致的 source 批次会阻止导出，避免把缺失结果误当成没有 source。
导出和扫描时都校验 UAST 索引对应的源码哈希。

在 `LLM-check` 目录导出（选择尚不存在的输出文件）：

```bash
PYTHONDONTWRITEBYTECODE=1 /data/fyn/conda_envs/laya/bin/python -B export_yasa_inputs.py \
  --jev-run runs/jev-ctfd-application-bindings-v3 \
  --source-run runs/jev-sources-ctfd-application-v1 \
  --sink-run runs/jev-sinks-ctfd-application-v2 \
  --sink-links runs/jev-sinks-ctfd-application-v2/callgraph-links-confidence-gt-0.5 \
  --out runs/jev-sinks-ctfd-application-v2/yasa-propagation-ctfd-v2/yasa-input.json
```

上述 CTFd 反查范围为 187 个入口、276 条 source 判断、511 个 sink。
其中 120 个 sink 没有被 Jev 选中的危险参数，保留在输入和统计里，不自动检查所有参数。
source 若在多个入口中有不同判断，保留各入口的判断，只在关联入口的执行期间生效。
没有 source 的入口仍会执行；不补充旧规则识别出的 source。
历史 `yasa-llm-input/v1` 文件只有入口/source，当前严格替换模式要求重新导出 v2，防止继续使用原生 sink。

在 **YASA-Engine 根目录**启动扫描：

```bash
node --max-old-space-size=16384 --require tsx/cjs src/main.ts \
  --sourcePath CTFd \
  --analyzer PythonAnalyzer \
  --checkerPackIds taint-flow-python-default \
  --ruleConfigFile resource/example-rule-config/rule_config_python.json \
  --llmInputFile LLM-check/runs/jev-sinks-ctfd-application-v2/yasa-propagation-ctfd-v2/yasa-input.json \
  --uastSDKPath my-release-bundle/uast4py-linux-amd64 \
  --taintTraceOutputStrategy full \
  --report LLM-check/runs/jev-sinks-ctfd-application-v2/yasa-propagation-ctfd-v2/report
```

必须使用当前源码启动，或重新编译后的引擎；现有打包二进制没有新参数。
`--uastSDKPath` 可替换为本机解析器路径。报告目录使用新目录，避免清理已有实验报告。

`--llmInputFile` 是显式替换模式：导入入口替代自动识别、调用图/文件入口及规则文件中的入口；
原有 source 标记及 Python sink 匹配被关闭，YASA 的传播和框架调用模型继续工作。
执行到导入的 sink 调用位置时，只检查 Jev 选中的位置参数、关键字参数或接收者。
没有匹配到导入 sink 的调用，即使命中旧 sink 规则也不会由该规则产生告警。
无法确定绑定的 `*args` / `**kwargs` 保留为未解析，不当作安全，也不回退为检查全部参数。
不传该参数时按原有流程扫描。当前支持 Python 仓库，不与框架自动建模或分析上下文缓存的保存/加载混用。
导入保留原始用途、形成方式和置信度；这些标签作为元数据，实际入口和 source 的绑定依据是代码位置。

入口用文件、定义起止行列匹配；重名方法和 overload 分别绑定。嵌套函数创建词法函数作用域，
不会把外层工厂额外当成入口；这不等于已经执行外层工厂、恢复了其运行时闭包变量。
默认直接分析入口原始方法体，跳过装饰器；导出时可用 `--execute-decorators` 改为执行装饰器。
跳过装饰器时，装饰器内部的检查和输入转换不会自动执行，应结合结果解释覆盖范围。

source 按精确源码位置处理：参数在实际绑定后标记，调用返回值、属性和下标读取在对应表达式求值后标记，
使用原有 `PYTHON_INPUT` 污点标签和 `SOURCE:` 路径，再交给引擎传播和导入 sink 参数检测。
不会仅凭名称匹配其他函数或其他位置。同一辅助 source 只在原始 Jev 判断关联的入口下生效。

扫描输出：

- `report.sarif`：传播告警；`sinkInfo.llm` 保留原始 sink 判断、选中参数及其置信度。
- `llm-input-diagnostics.json`：入口/source/sink 的匹配及执行统计、未选参数和参数绑定未解析数；每个入口结束后更新。
- `source-to-sink.csv`：整理后包含 sink ID、原始类别、选中参数及 sink/参数置信度。
- 日志中的 `[LLM]`：导入、位置匹配和实际 source 标记统计。

“匹配到 UAST”不等于“执行到”。动态关系、未执行分支、缺失闭包绑定等仍可能使某些 source 未触发；
这些位置保留在诊断文件中，不静默替换成旧规则或按同名位置回退。
告警类别使用 `LLM:<原始 sink_kind>`，不依据函数名改写模型标签或自动宣称命中某个 CWE。
当前 sink 任务没有输出各 sink 适用的 sanitizer 定义；v2 输出的是污点进入选中参数的传播告警，
不能单凭传播命中认定已经绕过校验或证明漏洞可利用。

以下为只导入入口/source、继续使用原生 sink 的历史 v1 实验，不能视为当前 v2 结果：
全 CTFd 256/256 入口、318/318 source 位置绑定成功；小型回归覆盖四种 source、
嵌套函数、同名方法、跳过装饰器、按入口隔离 source 及关闭导入后的原有扫描。
CTFd 三入口小样保存于 `runs/jev-sources-ctfd-application-v1/yasa-smoke-report`：3 条 source 均成功标记，
产生 1 条 `plugin` 参数到 `open(...)` 的路径遍历告警。这份小样不代表完整扫描结果。

该历史全入口污点扫描使用 `yasa-report-v2`，日志为
`runs/jev-sources-ctfd-application-v1/yasa-full-run-v2.log`。
第一次尝试保留在 `yasa-full-run.log`，因空净化规则仍遍历大型 receiver 图而中断；
修复只跳过不可能产生净化匹配的空规则遍历，不更改入口、source、sink 或净化规则。
原尝试状态记录在 `yasa-full-attempt-v1.json`。

`summarize_yasa_taint.py` 可以自动等待并整理最终报告。当前整理器已启动，输出到
`runs/jev-sources-ctfd-application-v1/yasa-full-summary-v2`：

- `status.json`：运行进度，每 30 秒更新；`running` 不代表已经完成。
- `SUMMARY.md` / `summary.json`：扫描结束后生成的统计和导入位置核对结果。
- `source-to-sink.csv`：每条告警的入口、source、sink，检查其 source 是否属于该入口的原始导入判断。
- `untriggered-sources.csv`：模型判断为 source 但本轮未成功标记的位置，不能当作非 source。

整理脚本不调用 API，也不修改扫描标签。完整报告尚未生成时，只保存进度，不提前宣称完成。
重新整理已有结果可在根目录运行（等待扫描时加 `--watch`）：

```bash
PYTHONDONTWRITEBYTECODE=1 /data/fyn/conda_envs/laya/bin/python -B LLM-check/summarize_yasa_taint.py \
  --input LLM-check/runs/jev-sources-ctfd-application-v1/yasa-input.json \
  --report LLM-check/runs/jev-sources-ctfd-application-v1/yasa-report-v2 \
  --log LLM-check/runs/jev-sources-ctfd-application-v1/yasa-full-run-v2.log \
  --repo CTFd \
  --out LLM-check/runs/jev-sources-ctfd-application-v1/yasa-full-summary-v2
```

### Jev 逐调用点识别 sink

功能入口为 `jev_sinks.py`，上下文构建为 `sink_context.py`，提示词为 `prompts/sink_jev_v1.json`。
每个模型目标是一处 Python 调用，输出是否为潜在 sink、操作类型、危险实参/receiver 和原始概率。
这一步不判断输入是否可控，不直接判断漏洞，也不读取 YASA sink 规则或参考标注作为答案。

长函数不会整体输入。每个调用保留完整调用表达式及参数、所属函数签名，并选取相关导入/别名、
局部赋值、外层控制条件、少量本地被调用函数及直接使用位置。
默认最多 16,000 字符、10 条相关赋值、2 层赋值依赖、2 个本地被调用函数（每个最多 100 行）、2 处直接调用证据。
超出预算的辅助证据记录在 `contexts/`，完整调用不截断；必需输入本身超预算时该候选不提交。
这是用于判断调用语义的局部上下文，不是已完成的反向污点切片。

`.env` 的 `TYPESAFE_BASE_URL` 填服务根地址或以 `/v1` 结尾的基础地址；不要填完整的 `/v1/systemone` 路径。
程序使用 Jev 的 choice 接口，实际路径为 `/v1/systemone`，并携带 `YASA-Jev-Client/1.0` 客户端标识。

在 `LLM-check` 目录运行，输出目录选择尚未使用的名称：

```bash
PYTHONDONTWRITEBYTECODE=1 /data/fyn/conda_envs/laya/bin/python -B jev_sinks.py prepare \
  --jev-run runs/jev-ctfd-application-bindings-v3 \
  --out runs/jev-sinks-ctfd-application-v2

PYTHONDONTWRITEBYTECODE=1 /data/fyn/conda_envs/laya/bin/python -B jev_sinks.py run \
  --out runs/jev-sinks-ctfd-application-v2 --workers 4

PYTHONDONTWRITEBYTECODE=1 /data/fyn/conda_envs/laya/bin/python -B jev_sinks.py summarize \
  --out runs/jev-sinks-ctfd-application-v2
```

`prepare` 只提取输入。默认覆盖业务文件里的调用点，不用入口可达性做预筛选；可用 `--function`、
`--candidate` 或 `--limit` 选择小样。`run` 先问是否为 sink，只对原始答案 yes 的候选继续询问类型和参数，
再次执行相同 run 命令可复用已保存的回复。参数 selector 中 `positional_0` 是源码第一个位置实参，
`keyword_N` 保留对应关键字名称，`receiver` 是方法调用的接收对象；`*args` 和 `**kwargs` 的实际展开位置未被证明。

输出：`possible-sinks.csv`/JSON 为模型选 yes 的调用，`candidate-results.csv` 为全部判断，
`results.json` 保留参数选择及原始概率，`state-text/` 为精简输入，`requests/`、`responses/` 为实际请求和回复。
`summary.json`、`statistics.txt` 记录数量和 API 用量。模型未选出危险参数时保留原始结果，不自动补选。

CTFd 已准备 7,500 个业务调用点。已完成的 8 调用小样在 `runs/jev-sinks-ctfd-pilot-v1`：
3 个潜在 sink、5 个非 sink、0 unknown、0 失败，耗时约 6.94 秒，11 次请求，17,586 tokens。
`open` 选中路径实参，`render_template_string` 选中模板实参；SQL execute 被判为 sink，但两个参数角色问题均回答 no。
原始答案完整保留，不能把这 8 个样例当作全库准确率。全量扫描结果写入 `runs/jev-sinks-ctfd-application-v2`。
本次小样命令临时指定了 `TYPESAFE_BASE_URL=https://api.site`，没有修改用户 `.env`。

### 把 Jev sink、入口和 source 关联到 YASA 调用图

`link_sink_candidates.py` 离线读取现有三轮结果，不调用模型。sink 扫描仍在运行时也可以执行：
每次只使用启动时读到的已保存结果；扫描结束后重新执行同一命令，更新同一输出目录。
在 **YASA-Engine 根目录**运行：

```bash
PYTHONDONTWRITEBYTECODE=1 /data/fyn/conda_envs/laya/bin/python -B LLM-check/link_sink_candidates.py \
  --sink-run LLM-check/runs/jev-sinks-ctfd-application-v2 \
  --entrypoint-run LLM-check/runs/jev-ctfd-application-bindings-v3 \
  --source-run LLM-check/runs/jev-sources-ctfd-application-v1 \
  --callgraph artifacts/ctfd-full-callgraph-20261026/report/callgraph.json \
  --out LLM-check/runs/jev-sinks-ctfd-application-v2/callgraph-links
```

按 sink 置信度选择反查起点时，在命令中添加 `--sink-confidence-gt 0.5`，
并将 `--out` 改为 `LLM-check/runs/jev-sinks-ctfd-application-v2/callgraph-links-confidence-gt-0.5`。
该参数严格筛选原始 `sink_answer.confidence > 0.5` 的模型阳性调用点，等于 0.5 的不纳入；
不是按 `probabilities.yes` 筛选。汇总分别记录扫描中的全部阳性 sink、本次反查数量和被阈值排除的数量。
筛选只决定反查起点，保留模型原始判断和分数。

脚本先按 UAST 中所属函数的文件及完整定义行列，匹配调用图节点；同一源码定义的多个图节点
合并用于函数级可达性，原图节点和边仍可回查。模块/类初始化中的调用、没有匹配函数节点的 sink
单独保留；不按重名函数回退绑定。sink 调用自身是否有对应的调用图边也单独记录。

从 sink 所在函数沿所有调用者反查，不限制深度，不在遇到第一个入口时停止。每对入口/sink
保存一条最短调用链供查看，不枚举所有可能路径；sink 位于入口本体时允许零跳关系。
外部或缺少定义的节点也参与遍历，查看路径经过这些节点时标为待确认。

关联 source 时保留它原来的入口归属，包括入口调用的其他辅助函数中的 source；不要求 source
出现在这条最短调用链上。`upstream_source_ids` 另列所属函数位于反查范围的既有 source，
不会把这些 source 改挂到其他入口。没有入口、source 或被选中的 sink 参数都不删除该 sink。

主要输出：

- `associations.csv`：每行一组 sink/候选入口，包含 sink 位置、参数及置信度、入口及置信度、
  source 位置/表达式/置信度、调用关系与缺失信息；无入口的 sink 也保留一行。
- `sink-links.json`：每个 sink 的完整判断、所有候选入口、source ID 和查看路径。
- `graph-nodes.json`：查看路径节点的名称和定义位置；路径中的边 ID 对应输入调用图。
- `entrypoints.json`、`sources.json`：原始入口和 source 信息，保留模型概率及置信度。
- `unknown-sources.json`、`pending-calls.csv`：source 未决判断和 sink unknown/失败项；
  尚未请求的调用数量另列在汇总中，不当作非 sink。
- `summary.json`、`SUMMARY.md`：快照覆盖数量、关联成功数量、涉及入口数和缺失情况。

这些输出表示函数级候选关系，尚未证明 source 的数据进入 sink 指定参数，也不是漏洞报告。
各阶段模型置信度分别保留，不合成链路置信度，不应用阈值改变原始标签。

### 入口识别的参考评估

source 的候选级参考评测另见 [source 评测报告](evaluations/ctfd-jev-sources-static-v1/REPORT.md)
及 [口径和错误分析](evaluations/ctfd-jev-sources-static-v1/NOTES.md)。
使用独立的 [source 静态参考](annotations/ctfd-sources-static-v1/README.md)，不能直接套用函数级入口标签。
它由显式静态规则生成、没有 source 预测读入、尚无独立人工逐点复核；分数只适用于给定候选集。
585 个参考 unknown 单列排除，模型 unknown 不冒充 TN；Accuracy 同时给出全负基线和 Balanced Accuracy。
候选和标注哈希、原始 API 回复均核对；Jev 的原始标签和概率保持不变，评测不调用 API。

用户已选择 `annotations/ctfd-application-v1` 作为当前实验的 ground truth。
用已有结果离线评估，不调用 API、不改变标注或模型输出：

```bash
/data/fyn/conda_envs/laya/bin/python evaluate_ctfd_reference.py \
  --run runs/jev-ctfd-application-bindings-v3 \
  --gold annotations/ctfd-application-v1 \
  --out evaluations/ctfd-jev-reference-v1
```

每次评估使用新输出目录，保存 ground truth、policy 和 predictions 快照与哈希。
以 case_id 匹配并检查函数身份、源码定义、仓库版本、索引与请求哈希；不会按名称合并 getter/setter。
42 个 ground truth unknown 独立保留，不进入二元识别/分类评分。
模型 unknown、请求失败和未执行分别计数；确定回答召回率与包含未决缺口的全正例召回率同时报告。
形成方式按多标签精确匹配和 micro P/R/F1 评分，用途命中 entrypoint_kinds 任一确认用途即算匹配。
`REPORT.md` 是阅读版，`metrics.json` 包含完整指标，false-positives/false-negatives/classification-errors CSV 可逐条复核。

```bash
python3 -m unittest discover -s LLM-check -p 'test_*.py' -v
```

离线测试覆盖同名函数隔离、别名导入、局部遮蔽、作用域规则、预算、证据校验、API 请求/重试、
并发、断点续跑和缓存失效。HTTP 层使用本地模拟，不发送真实 API 请求。
