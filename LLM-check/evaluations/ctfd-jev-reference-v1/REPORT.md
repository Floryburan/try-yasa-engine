# Jev 对 CTFd ground truth 的评估

Ground truth：用户已选定的 ctfd-application-v1。保留原始标注与模型输出，本报告只做离线匹配计分。

按 case_id 精确匹配，并验证函数身份、源码定义、仓库版本、索引和请求哈希；不按函数名模糊匹配。

## 评估范围

| 项目 | 数量 |
|---|---:|
| ground_truth_total | 847 |
| ground_truth_positives | 392 |
| ground_truth_negatives | 413 |
| excluded_gold_unknown | 42 |
| predictions_available | 847 |
| successful_predictions | 847 |
| binary_decisions_scored | 804 |
| model_unknown | 1 |
| request_errors | 0 |
| not_attempted | 0 |

## 入口识别

| Ground truth / Jev | 是入口 | 非入口 | 不确定/失败/未执行 |
|---|---:|---:|---:|
| 是入口 | 253 | 138 | 1 |
| 非入口 | 1 | 412 | 0 |

| 指标 | 数值 | 分母说明 |
|---|---:|---|
| 精确率 | 99.61% | TP/(TP+FP)，排除 ground truth unknown |
| 全正例召回率 | 64.54% | TP/全部 392 个确定正例，不确定/失败/未执行没有被算作已找到 |
| F1（全正例召回口径） | 78.33% | 上述精确率与全正例召回率的调和平均 |
| 确定回答召回率 | 64.71% | TP/(TP+FN)，仅统计模型明确 yes/no 的正例 |
| 确定回答 F1 | 78.45% | 与确定回答召回率对应 |
| 确定回答准确率 | 82.71% | (TP+TN)/804 |
| 全部确定真值的正确比例 | 82.61% | (TP+TN)/805，保留模型未决造成的缺口 |
| 负例误报率 | 0.24% | FP/(FP+TN) |

FN 只表示模型明确回答 no 的真实入口；模型 unknown、请求失败和缺失分别保留，不伪装为 FN 或 TN。
ground truth 的 unknown 条目不进入二元识别和分类评分。

## 按标注主用途的入口召回

| 用途 | 真值入口 | 找到 | 明确漏报 | 未决 | 召回率 |
|---|---:|---:|---:|---:|---:|
| cli | 6 | 6 | 0 | 0 | 100.00% |
| event | 6 | 2 | 4 | 0 | 33.33% |
| http | 225 | 224 | 1 | 0 | 99.56% |
| lifecycle | 28 | 17 | 11 | 0 | 60.71% |
| other | 127 | 4 | 122 | 1 | 3.15% |

## 已正确识别入口后的分类

仅在 253 个 TP 上评价分类，避免把识别漏报与分类错误混在一起。

- 形成方式完全匹配：1/253（0.40%）。
- 用途匹配：242/253（95.65%）；命中 entrypoint_kinds 任一合法用途即可。
- 形成方式 micro P/R/F1：46.70% / 93.94% / 62.38%。

| 形成方式 | 真值支持数 | TP | FP（多选） | FN（未命中） | unknown | 精确率 | 召回率 | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| registration | 3 | 3 | 238 | 0 | 0 | 1.24% | 100.00% | 2.46% |
| inheritance | 162 | 146 | 0 | 16 | 0 | 100.00% | 90.12% | 94.81% |
| interface_implementation | 2 | 2 | 7 | 0 | 0 | 22.22% | 100.00% | 36.36% |
| configuration | 9 | 1 | 200 | 8 | 6 | 0.50% | 11.11% | 0.95% |
| callback | 18 | 17 | 15 | 1 | 0 | 53.12% | 94.44% | 68.00% |
| decorator | 234 | 234 | 0 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| other | 1 | 0 | 0 | 1 | 0 | n/a | 0.00% | 0.00% |

形成方式 exact match 要求全部标签一致，任一分类问题 unknown 不计完全正确。micro 指标按实际输出 yes 的标签评分，未决标签另列。
端到端形成方式 micro 指标另见 metrics.json：未找到的正例标签作为未恢复标签，负例上预测出的标签作为额外标签。

## 按入口子类型定位漏报

子类型允许重叠，下面各行不能直接相加当作函数总数。

| 子类型 | 真值入口 | 找到 | 明确漏报 | 未决 | 召回率 |
|---|---:|---:|---:|---:|---:|
| application_factory | 1 | 1 | 0 | 0 | 100.00% |
| babel_locale_selector | 1 | 0 | 1 | 0 | 0.00% |
| challenge_plugin_method | 12 | 4 | 8 | 0 | 33.33% |
| challenge_scoring_strategy | 4 | 0 | 4 | 0 | 0.00% |
| cli_subcommand_dispatch | 1 | 1 | 0 | 0 | 100.00% |
| click_command | 5 | 5 | 0 | 0 | 100.00% |
| configparser_interpolation | 1 | 0 | 1 | 0 | 0.00% |
| configured_email_provider | 2 | 0 | 2 | 0 | 0.00% |
| configured_event_manager | 6 | 2 | 4 | 0 | 33.33% |
| configured_uploader_method | 12 | 0 | 12 | 0 | 0.00% |
| flag_plugin_method | 2 | 0 | 2 | 0 | 0.00% |
| flask_caching_key_callback | 1 | 0 | 1 | 0 | 0.00% |
| flask_environment_hook | 1 | 0 | 1 | 0 | 0.00% |
| flask_error_handler | 1 | 1 | 0 | 0 | 100.00% |
| flask_request_factory | 1 | 0 | 1 | 0 | 0.00% |
| flask_request_hook | 11 | 8 | 3 | 0 | 72.73% |
| flask_restx_resource_method | 155 | 155 | 0 | 0 | 100.00% |
| flask_route | 66 | 66 | 0 | 0 | 100.00% |
| flask_session_interface | 2 | 2 | 0 | 0 | 100.00% |
| flask_url_adapter_hook | 1 | 0 | 1 | 0 | 0.00% |
| gevent_task | 1 | 0 | 1 | 0 | 0.00% |
| jinja_environment_factory | 1 | 0 | 1 | 0 | 0.00% |
| jinja_environment_hook | 1 | 0 | 1 | 0 | 0.00% |
| jinja_filter | 6 | 0 | 6 | 0 | 0.00% |
| jinja_global_function | 30 | 0 | 30 | 0 | 0.00% |
| jinja_loader_hook | 1 | 0 | 1 | 0 | 0.00% |
| jinja_namespace_member | 30 | 0 | 30 | 0 | 0.00% |
| marshmallow_field_deserializer | 1 | 0 | 1 | 0 | 0.00% |
| marshmallow_field_validator | 2 | 0 | 2 | 0 | 0.00% |
| marshmallow_hook | 14 | 0 | 14 | 0 | 0.00% |
| marshmallow_nested_schema_factory | 2 | 0 | 2 | 0 | 0.00% |
| marshmallow_validator | 1 | 0 | 1 | 0 | 0.00% |
| plugin_loader_hook | 3 | 3 | 0 | 0 | 100.00% |
| plugin_migration_upgrade | 3 | 3 | 0 | 0 | 100.00% |
| registered_asset_handler | 2 | 2 | 0 | 0 | 100.00% |
| social_share_strategy | 2 | 0 | 1 | 1 | 0.00% |
| sqlalchemy_attribute_validator | 2 | 0 | 2 | 0 | 0.00% |
| sqlalchemy_compiler_hook | 1 | 0 | 1 | 0 | 0.00% |
| sqlalchemy_connect_listener | 1 | 0 | 1 | 0 | 0.00% |
| streaming_response_body | 1 | 0 | 1 | 0 | 0.00% |
| wtforms_bound_field_factory | 1 | 0 | 1 | 0 | 0.00% |
| wtforms_csrf_hook | 1 | 0 | 1 | 0 | 0.00% |

## 逐条结果

误报见 false-positives.csv，明确漏报见 false-negatives.csv；unresolved.csv 与 excluded-gold-unknown.csv 分开保存。
分类错误见 classification-errors.csv；全量配对、真值理由与证据位置见 all-functions.csv / details.json。

## 实验解释

本次按用户指定的静态参考集作为 ground truth。其来源、边界和 42 个不确定项保留在原始数据集中。
评测没有修改标注、阈值筛选预测、人工纠正回答或重新调用模型；结果仅针对该固定仓库和标注口径。
