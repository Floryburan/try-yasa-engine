# Jev 对 django-helpdesk ground truth 的评估

Ground truth：django-helpdesk-application-v1。保留原始标注与模型输出，本报告只做离线匹配计分。

按 case_id 精确匹配，并验证函数身份、源码定义、仓库版本、索引和请求哈希；不按函数名模糊匹配。

## 评估范围

| 项目 | 数量 |
|---|---:|
| ground_truth_total | 425 |
| ground_truth_positives | 203 |
| ground_truth_negatives | 218 |
| excluded_gold_unknown | 4 |
| predictions_available | 425 |
| successful_predictions | 398 |
| binary_decisions_scored | 394 |
| model_unknown | 0 |
| request_errors | 27 |
| not_attempted | 0 |

## 入口识别

| Ground truth / Jev | 是入口 | 非入口 | 不确定/失败/未执行 |
|---|---:|---:|---:|
| 是入口 | 85 | 105 | 13 |
| 非入口 | 1 | 203 | 14 |

| 指标 | 数值 | 分母说明 |
|---|---:|---|
| 精确率 | 98.84% | TP/(TP+FP)，排除 ground truth unknown |
| 全正例召回率 | 41.87% | TP/全部 203 个确定正例，不确定/失败/未执行没有被算作已找到 |
| F1（全正例召回口径） | 58.82% | 上述精确率与全正例召回率的调和平均 |
| 确定回答召回率 | 44.74% | TP/(TP+FN)，仅统计模型明确 yes/no 的正例 |
| 确定回答 F1 | 61.59% | 与确定回答召回率对应 |
| 确定回答准确率 | 73.10% | (TP+TN)/394 |
| 全部确定真值的正确比例 | 68.41% | (TP+TN)/421，保留模型未决造成的缺口 |
| 负例误报率 | 0.49% | FP/(FP+TN) |

FN 只表示模型明确回答 no 的真实入口；模型 unknown、请求失败和缺失分别保留，不伪装为 FN 或 TN。
ground truth 的 unknown 条目不进入二元识别和分类评分。

## 按标注主用途的入口召回

| 用途 | 真值入口 | 找到 | 明确漏报 | 未决 | 召回率 |
|---|---:|---:|---:|---:|---:|
| cli | 10 | 10 | 0 | 0 | 100.00% |
| event | 4 | 4 | 0 | 0 | 100.00% |
| http | 103 | 50 | 44 | 9 | 48.54% |
| lifecycle | 24 | 14 | 10 | 0 | 58.33% |
| other | 62 | 7 | 51 | 4 | 11.29% |

## 分范围统计

| 范围 | 函数 | TP | FP | FN | TN | GT 不确定 | 请求失败 | 精确率 | 全正例召回率 | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| migrations | 16 | 12 | 0 | 1 | 3 | 0 | 0 | 100.00% | 92.31% | 96.00% |
| runtime_application | 409 | 73 | 1 | 104 | 200 | 4 | 27 | 98.65% | 38.42% | 55.30% |

## 已正确识别入口后的分类

仅在 85 个 TP 上评价分类，避免把识别漏报与分类错误混在一起。

- 形成方式完全匹配：6/85（7.06%）。
- 用途匹配：66/85（77.65%）；命中 entrypoint_kinds 任一合法用途即可。
- 形成方式 micro P/R/F1：57.82% / 93.13% / 71.35%。

| 形成方式 | 真值支持数 | TP | FP（多选） | FN（未命中） | unknown | 精确率 | 召回率 | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| registration | 63 | 62 | 6 | 1 | 0 | 91.18% | 98.41% | 94.66% |
| inheritance | 18 | 18 | 0 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| interface_implementation | 0 | 0 | 16 | 0 | 0 | 0.00% | n/a | 0.00% |
| configuration | 4 | 1 | 67 | 3 | 1 | 1.47% | 25.00% | 2.78% |
| callback | 37 | 34 | 0 | 3 | 0 | 100.00% | 91.89% | 95.77% |
| decorator | 8 | 7 | 0 | 1 | 0 | 100.00% | 87.50% | 93.33% |
| other | 1 | 0 | 0 | 1 | 0 | n/a | 0.00% | 0.00% |

形成方式 exact match 要求全部标签一致，任一分类问题 unknown 不计完全正确。micro 指标按实际输出 yes 的标签评分，未决标签另列。
端到端形成方式 micro 指标另见 metrics.json：未找到的正例标签作为未恢复标签，负例上预测出的标签作为额外标签。

## 按入口子类型定位漏报

子类型允许重叠，下面各行不能直接相加当作函数总数。

| 子类型 | 真值入口 | 找到 | 明确漏报 | 未决 | 召回率 |
|---|---:|---:|---:|---:|---:|
| attachment_path_implementation | 2 | 0 | 2 | 0 | 0.00% |
| celery_shared_task | 1 | 1 | 0 | 0 | 100.00% |
| configured_settings_callback | 3 | 0 | 3 | 0 | 0.00% |
| django_admin_delete_hook | 1 | 1 | 0 | 0 | 100.00% |
| django_admin_display | 4 | 1 | 3 | 0 | 25.00% |
| django_app_ready | 1 | 1 | 0 | 0 | 100.00% |
| django_authorization_predicate | 1 | 0 | 1 | 0 | 0.00% |
| django_class_view_hook | 28 | 1 | 19 | 8 | 3.57% |
| django_data_migration | 13 | 12 | 1 | 0 | 92.31% |
| django_feed_hook | 20 | 1 | 19 | 0 | 5.00% |
| django_field_default | 7 | 0 | 7 | 0 | 0.00% |
| django_field_upload_to | 1 | 1 | 0 | 0 | 100.00% |
| django_field_validators | 2 | 0 | 2 | 0 | 0.00% |
| django_form_clean_hook | 3 | 0 | 3 | 0 | 0.00% |
| django_management_command | 9 | 9 | 0 | 0 | 100.00% |
| django_manager_hook | 1 | 0 | 1 | 0 | 0.00% |
| django_model_absolute_url | 4 | 0 | 4 | 0 | 0.00% |
| django_model_clean_hook | 1 | 0 | 1 | 0 | 0.00% |
| django_model_delete_hook | 1 | 0 | 1 | 0 | 0.00% |
| django_model_save_hook | 6 | 0 | 6 | 0 | 0.00% |
| django_signal_receiver | 3 | 3 | 0 | 0 | 100.00% |
| django_template_registration | 13 | 3 | 6 | 4 | 23.08% |
| django_url_function | 46 | 45 | 0 | 1 | 97.83% |
| drf_serializer_hook | 5 | 2 | 3 | 0 | 40.00% |
| drf_serializer_method_field | 16 | 0 | 16 | 0 | 0.00% |
| drf_viewset_hook | 9 | 3 | 6 | 0 | 33.33% |
| markdown_extension_hook | 1 | 0 | 1 | 0 | 0.00% |
| python_module_main | 1 | 1 | 0 | 0 | 100.00% |

## 逐条结果

误报见 false-positives.csv，明确漏报见 false-negatives.csv；unresolved.csv 与 excluded-gold-unknown.csv 分开保存。
分类错误见 classification-errors.csv；全量配对、真值理由与证据位置见 all-functions.csv / details.json。

## 实验解释

本次按用户指定的静态参考集作为 ground truth。其来源、边界和 4 个不确定项保留在原始数据集中。
评测没有修改标注、阈值筛选预测、人工纠正回答或重新调用模型；结果仅针对该固定仓库和标注口径。
