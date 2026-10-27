# django-helpdesk Jev 完整结果（补跑后）

扫描目录：`jev-django-helpdesk-20261026-204401`。425 个函数全部成功，无失败或模型二分类 unknown。实际模型：jev-1.14.0。

以此前冻结的 AI 辅助静态参考作为当前实验 ground truth；4 个 GT 不确定函数排除评分。完整评测与源码证据位置见 [REPORT.md](REPORT.md)。

## 扫描与用量

| 项目 | 数量 |
|---|---:|
| 目标函数 | 425 |
| 成功函数 | 425 |
| 模型入口 | 93 |
| 模型非入口 | 332 |
| 请求失败 | 0 |
| 模型二分类 unknown | 0 |
| 补跑耗时 | 57.436 秒 |
| 复用已有成功函数 | 398 |
| 补跑函数 | 27 |
| 补跑 API 请求 | 80 |
| 补跑输入 tokens | 73,976 |
| 补跑输出 tokens | 3,538 |
| 补跑总 tokens | 77,514 |
| 当前保存 API 响应 | 1,169 |
| 当前保存输入 tokens | 1,569,513 |
| 当前保存输出 tokens | 51,425 |
| 当前保存总 tokens | 1,620,938 |
| 两轮已记录 run 耗时合计 | 1301.774 秒（约 21 分 42 秒） |

保存的响应数不同于历史请求尝试数；上一轮 27 次网络失败没有成功响应。token 为有 usage 的记录合计，不推算实际账单；run 耗时不含准备上下文，也不含两轮间的空闲时间。

## 识别结果

| GT / Jev | 判为入口 | 判为非入口 |
|---|---:|---:|
| 真实入口 | 92（TP） | 111（FN） |
| 真实非入口 | 1（FP） | 217（TN） |

425 个函数中，4 个 GT unknown 均被模型判为 no，仍按原口径排除；参与评分共 421 个。

| 指标 | 补跑前 | 补跑后 |
|---|---:|---:|
| 精确率 | 98.84% | 98.92% |
| 全部正例召回率 | 41.87% | 45.32% |
| F1 | 58.82% | 62.16% |
| 准确率（已成功且 GT 确定） | 73.10% | 73.40% |

补跑前后准确率分母不同：394 → 421。补跑前召回率保留失败导致的缺口，补跑后已全部确定。

补跑 27 个函数产生 7 个 yes、20 个 no；7 个 yes 全为真入口，20 个 no 包含 14 个真负例和 6 个漏报。因此 FN 从 105 增加到 111；原来的 398 个成功结果完全未变。

## 分范围

| 范围 | 函数 | GT 正例 | TP | FP | FN | TN | 精确率 | 召回率 | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| migrations | 16 | 13 | 12 | 0 | 1 | 3 | 100.00% | 92.31% | 96.00% |
| runtime_application | 409 | 190 | 80 | 1 | 110 | 214 | 98.77% | 42.11% | 59.04% |

## 分类效果（仅 92 个 TP）

- 形成方式完整集合匹配：6/92，6.52%。
- 用途命中 entrypoint_kinds 任一合法标签：72/92，78.26%。
- TP 内形成方式 micro F1：70.90%。
- 含漏报影响的端到端形成方式 micro F1：40.06%。

形成方式整组匹配数量仍为 6，分母从 85 增至 92，匹配率由 7.06% 变为 6.52%。多标签单独命中不能代替完整集合正确。

| 形成方式 | 标签 TP | 多选 FP | 漏选 FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| registration | 68 | 6 | 2 | 91.89% | 97.14% | 94.44% |
| inheritance | 22 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| interface_implementation | 0 | 17 | 0 | 0.00% | — | 0.00% |
| configuration | 1 | 72 | 3 | 1.37% | 25.00% | 2.60% |
| callback | 36 | 3 | 3 | 92.31% | 92.31% | 92.31% |
| decorator | 7 | 2 | 1 | 77.78% | 87.50% | 82.35% |
| other | 0 | 0 | 1 | — | 0.00% | 0.00% |

上表仅对已正确找到的入口分类。比如 inheritance 在这 92 个 TP 内 P/R 为 100%，但全体真值 104 个带 inheritance 的函数只恢复出 22 个，端到端该标签召回率为 21.15%。

## 按子类型的入口识别

| 子类型 | 真值入口 | 找到 | 漏报 | 召回率 |
|---|---:|---:|---:|---:|
| attachment_path_implementation | 2 | 0 | 2 | 0.00% |
| celery_shared_task | 1 | 1 | 0 | 100.00% |
| configured_settings_callback | 3 | 0 | 3 | 0.00% |
| django_admin_delete_hook | 1 | 1 | 0 | 100.00% |
| django_admin_display | 4 | 1 | 3 | 25.00% |
| django_app_ready | 1 | 1 | 0 | 100.00% |
| django_authorization_predicate | 1 | 0 | 1 | 0.00% |
| django_class_view_hook | 28 | 5 | 23 | 17.86% |
| django_data_migration | 13 | 12 | 1 | 92.31% |
| django_feed_hook | 20 | 1 | 19 | 5.00% |
| django_field_default | 7 | 0 | 7 | 0.00% |
| django_field_upload_to | 1 | 1 | 0 | 100.00% |
| django_field_validators | 2 | 0 | 2 | 0.00% |
| django_form_clean_hook | 3 | 0 | 3 | 0.00% |
| django_management_command | 9 | 9 | 0 | 100.00% |
| django_manager_hook | 1 | 0 | 1 | 0.00% |
| django_model_absolute_url | 4 | 0 | 4 | 0.00% |
| django_model_clean_hook | 1 | 0 | 1 | 0.00% |
| django_model_delete_hook | 1 | 0 | 1 | 0.00% |
| django_model_save_hook | 6 | 0 | 6 | 0.00% |
| django_signal_receiver | 3 | 3 | 0 | 100.00% |
| django_template_registration | 13 | 5 | 8 | 38.46% |
| django_url_function | 46 | 46 | 0 | 100.00% |
| drf_serializer_hook | 5 | 2 | 3 | 40.00% |
| drf_serializer_method_field | 16 | 0 | 16 | 0.00% |
| drf_viewset_hook | 9 | 3 | 6 | 33.33% |
| markdown_extension_hook | 1 | 0 | 1 | 0.00% |
| python_module_main | 1 | 1 | 0 | 100.00% |

子类型可重叠，不能相加作为函数总数；上表找到只表示识别为入口，不保证形成方式/用途全部正确。

## 主要发现

- URL 函数全部找到：46/46。
- CBV 钩子 5/28，Feed 方法 1/20，SerializerMethodField 回调 0/16，仍有明显漏报。
- configuration 多选 72 个标签，interface_implementation 多选 17 个标签；这些是在 TP 内的多标签错误，不是二分类函数误报数。
- 唯一二分类误报仍为 helpdesk.views.staff.redirect_from_chosen_ticket。
- 入口 yes / 用途 none 的两条矛盾回复仍保留：models.attachment_path、templatetags.bootstrap5_form.is_checkbox；未改写输出。

本次只做离线评估，没有调用 API、修改模型结果或调整 ground truth；保留上次 v1 报告，当前为 v2。
