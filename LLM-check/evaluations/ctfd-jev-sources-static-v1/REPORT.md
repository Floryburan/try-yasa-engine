# CTFd Jev source 参考评测

这是候选集上的 AI 辅助静态参考评测，无独立人工复核，不是已验证的全仓真实准确率。
参考构建只读取源码、无标签候选库存及独立入口静态参考；没有读取 source 预测/概率或 YASA 报告。
候选集受前一阶段入口选择和一层辅助扩展影响，不能评估未进入候选集的真实 source。

主口径：外部输入起点；已作为 source 的请求承载形参，其后续读取属于传播。
位置级检测：任一入口下原始答案为 yes 即表示模型发现该位置；不对原始入口级判断做投票或改标签。

| 指标 | 主口径，去重位置 |
|---|---:|
| accuracy | 97.52% |
| precision | 95.60% |
| recall | 71.70% |
| f1 | 81.94% |
| balanced_accuracy | 85.70% |
| specificity | 99.70% |
| all_negative_accuracy_baseline | 92.22% |
| reference_coverage | 90.31% |
| predicted_yes_reference_coverage | 100.00% |

```text
total                             : 6036
reference_known                   : 5451
reference_unknown_excluded        : 585
reference_positive                : 424
reference_negative                : 5027
tp                                : 304
fp                                : 14
fn_decided                        : 120
tn                                : 5012
unresolved_positive               : 0
unresolved_negative               : 1
```

参考 unknown 排除于二元评分，但单列保留；模型 unknown/失败不能冒充 TN，在主 Accuracy/Recall 分母保留。
Precision 只针对参考已定的模型 yes；参考未知的模型 yes 不擅自判为 FP，也不能认为已验证正确。

## 口径敏感性

若把请求承载形参上的每次直接请求 API 读取也算 source，指标变化如下：

| 指标 | 请求读取位置口径 |
|---|---:|
| accuracy | 97.60% |
| precision | 97.80% |
| recall | 71.66% |
| f1 | 82.71% |
| balanced_accuracy | 85.75% |

两个口径在参考标注之前定义，不按评测分数挑选。更换口径的行可在参考 annotations 的 request_read_policy_is_source 查到。
完整配对级、语法类别分组和冲突统计见 metrics.json；FP/FN 与参考 unknown 分别保存 CSV。
YASA 报告对照仅是告警路径 source 的精确位置重现率，见 yasa-reported-source-coverage.json；不把其余位置算成负例。
