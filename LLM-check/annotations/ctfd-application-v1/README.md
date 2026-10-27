# CTFd 全量业务函数入口参考标注

先阅读 [POLICY.md](POLICY.md)。本数据是 AI 辅助静态源码参考标注，**不是已经独立人工复核的金标准**。
它覆盖既有业务扫描的全部 847 个定义，不包含根目录 tests/migrations；也不包含 lambda 和模块顶层入口。
按路径归入业务范围的内嵌插件测试/迁移仍单独记录，具体边界见 policy。

## 查看文件

| 文件 | 用途 |
|---|---|
| [annotations.csv](annotations.csv) | 全量表，可用 Excel/表格软件筛选 true/false/unknown、类别和优先级 |
| [entrypoints.csv](entrypoints.csv) | 仅确定正例 |
| [non-entrypoints.csv](non-entrypoints.csv) | 仅负例参考判断 |
| [uncertain.csv](uncertain.csv) | 证据不足或入口口径边界，附候选类型，不能当负例 |
| [ANNOTATIONS.md](ANNOTATIONS.md) | 全量阅读版，带源码位置链接、类型和理由 |
| [annotations.json](annotations.json) | 每条完整源码、注册/配置/调用证据、哈希、启用条件和全部用途 |
| [FILE_COVERAGE.md](FILE_COVERAGE.md) | 154 个目标文件的覆盖计数 |
| [summary.json](summary.json) | 标注数量和类别统计 |
| [manifest.json](manifest.json) | 仓库版本、索引哈希、标注程序/策略版本和证据文件哈希 |

## 字段

- `is_entrypoint`: true / false / null。CSV 中 null 写为 unknown。
- `formation_types`: 确定形成方式，多标签；未知条目的候选放在 `candidate_formation_types`。
- `entrypoint_kind`: 展示用主要用途；`entrypoint_kinds` 保留同一函数的全部确认用途。
- `subtypes`: 更细的边界，如 flask_route、jinja_filter、marshmallow_hook、challenge_plugin_method。
- `evidence`: 文件、起止行、原始代码和 SHA-256。正例必须包含非目标本体的绑定/调度证据。
- `bindings`: 同一函数的多个注册/配置场景及各自类型、理由和启用条件。
- `review_priority`: 边界项或静态引用证据较弱的负例优先复核。
- `independent_human_review=false`: 尚未经过第二位标注者的独立人工复核；不能将它改名解释成人工标注。

## 用于评估时

1. 固定 policy 和当前 source commit，先完成独立复核，再冻结一份正式评测集。
2. 同一函数按 case_id/function_id 或 definition_identity 匹配，不能只按函数名匹配 getter/setter。
3. 未知标注、模型未知、请求失败和未请求分别统计，不能转成 TN。
4. 正例包含模板/扩展调度边界，**不等于独立 URL 个数**。可按 subtype 单独报告 HTTP 直接入口和扩展入口。
5. 注册方式允许重叠，但普通 route 的参数不自动算 configuration，装饰器内部注册也不自动叠加 registration。
6. 同时具有多种用途的函数，模型用途命中 entrypoint_kinds 任一项可以算场景匹配；不要仅凭主要用途误判。
7. 负例是基于角色和静态引用的参考判断，无法证明外部插件或自定义主题永远不能注册它们。

## 重建

在 LLM-check 目录：

```bash
PYTHONDONTWRITEBYTECODE=1 /data/fyn/conda_envs/laya/bin/python build_ctfd_reference.py
```

此程序只读取仓库源码与 UAST 索引，不读取模型预测，不调用 API，不启动 CTFd/数据库。
程序将重新生成本目录的数据文件；人工复核时请另存带 reviewer 信息的版本，不要直接覆盖后再重建。
