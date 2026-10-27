# django-helpdesk Jev 结果统计

扫描目录：`jev-django-helpdesk-20261026-204401`。模型别名 jev-latest，回复实际模型 jev-1.14.0。

按此前 AI 辅助静态参考 ground truth 评测；标注仍保留未独立人工复核的来源状态。当前有 27 个 SSL 请求失败，以下是当前保存结果的统计，未补跑或修改模型输出。

## 扫描与 API 用量

| 项目 | 数值 |
|---|---:|
| 包内 Python 文件 | 92 |
| 物理源码行（含注释/空行） | 14,598 |
| 函数总数 | 425 |
| 成功函数 | 398 |
| 模型入口 | 86 |
| 模型非入口 | 312 |
| 模型二分类 unknown | 0 |
| 请求失败函数 | 27 |
| 未执行函数 | 0 |
| 准备失败 | 0 |
| 耗时 | 20.74 分钟（1244.338 秒） |
| API 请求尝试 | 1116 |
| HTTP 成功响应 | 1089 |
| HTTP 错误 | 0 |
| 网络/SSL 错误 | 27 |
| 输入 tokens | 1,495,537 |
| 输出 tokens | 47,887 |
| 总 tokens | 1,543,424 |
| 平均 API 请求耗时 | 1101.48 ms |

请求数包含入口判断和后续分类，不等于函数数。token 为有服务端 usage 的记录合计，失败请求不代表未计费；不推算账户费用。

## 对照 ground truth

4 个 GT 不确定函数（本轮均被模型判 no）排除二分类评分；421 个确定真值中，394 个有成功的确定回答，27 个请求失败。

| GT / 模型 | 入口 | 非入口 | 请求失败 |
|---|---:|---:|---:|
| 入口 | 85 | 105 | 13 |
| 非入口 | 1 | 203 | 14 |

| 指标 | 数值 |
|---|---:|
| 精确率 | 98.84% |
| 全部 203 个正例的召回率（失败未恢复） | 41.87% |
| 对应 F1 | 58.82% |
| 仅成功且有明确回答的正例召回率 | 44.74% |
| 仅明确回答的 F1 | 61.59% |
| 仅明确回答的准确率（394 个） | 73.10% |

## 分范围

| 范围 | 函数 | TP | FP | FN | TN | 请求失败 | GT unknown | 精确率 | 全正例召回率 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| migrations | 16 | 12 | 0 | 1 | 3 | 0 | 0 | 100.00% | 92.31% |
| runtime_application | 409 | 73 | 1 | 104 | 200 | 27 | 4 | 98.65% | 38.42% |

## 分类效果（仅 85 个 TP）

- 形成方式完整集合匹配：6/85，7.06%。
- 用途匹配：66/85，77.65%。
用途命中 entrypoint_kinds 任一合法标签即算匹配；形成方式必须全部标签一致才算 exact match。

| 形成方式 | 标签 TP | 多选 FP | 漏选 FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| registration | 62 | 6 | 1 | 91.18% | 98.41% | 94.66% |
| inheritance | 18 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| interface_implementation | 0 | 16 | 0 | 0.00% | — | 0.00% |
| configuration | 1 | 67 | 3 | 1.47% | 25.00% | 2.78% |
| callback | 34 | 0 | 3 | 100.00% | 91.89% | 95.77% |
| decorator | 7 | 0 | 1 | 100.00% | 87.50% | 93.33% |
| other | 0 | 0 | 1 | — | 0.00% | 0.00% |

TP 内形成方式 micro P/R/F1：57.82% / 93.13% / 71.35%。
这些是已找到入口内的条件分类指标，不能代表所有真值入口的恢复能力。

## 子类型的识别情况

子类型可重叠；找到只表示识别为入口，不表示用途和形成方式也全部分对。

| 子类型 | GT 入口 | 找到 | 明确漏报 | 请求失败/未决 | 召回率 |
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

## 结果说明

- 普通 URL 函数识别出 45/46，另 1 个请求失败；未出现明确判 no 的 URL 函数漏报。
- CBV 钩子识别出 1/28（其中 8 个请求失败），Feed 方法识别出 1/20，DRF SerializerMethodField 回调识别出 0/16。
- 分类有明显多选：85 个 TP 中 configuration 只有 1 个标签选对、67 个标签多选；interface_implementation 多选 16 次。
- 12 个已找到的迁移回调用途被标为 cli，本集标注为 lifecycle。
- 唯一误报是 helpdesk.views.staff.redirect_from_chosen_ticket（src/helpdesk/views/staff.py:1012）。
- 两条回复存在入口 yes / 用途 none 的矛盾：models.attachment_path、templatetags.bootstrap5_form.is_checkbox；保留原输出计分。

完整评估见 [REPORT.md](REPORT.md)；逐条误报/漏报和分类错误见同目录 CSV。扫描原始统计快照也保存在本目录。

补跑只需对原目录执行 run，成功函数会复用；本次统计未触发补跑：

```bash
cd /data/fyn/yasa/YASA-Engine/LLM-check
PYTHONDONTWRITEBYTECODE=1 /data/fyn/conda_envs/laya/bin/python -B jev_scan.py run --out runs/jev-django-helpdesk-20261026-204401 --timeout 180
```

离线评估重跑时使用新的 --out，保留本次快照。评估程序支持 CTFd 和 django-helpdesk 的验证格式，7 项评估单元测试及全部 59 项离线测试通过。
