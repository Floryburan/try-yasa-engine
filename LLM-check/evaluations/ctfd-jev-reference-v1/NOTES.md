CTFd × Jev 入口识别实验统计（2026-10-26）

**1. 实验设置**

| 项目 | 内容 |
|---|---|
| 仓库 | CTFd 3.8.9 |
| Commit | `a751d1773df7f16341801831481eeb7b1ded18c2` |
| 模型 | jev-latest，实际返回 jev-1.14.0 |
| 输入 | 每个函数独立的精简源码上下文，含完整本体、直接引用、必要外层/导入和绑定证据 |
| 流程 | 先判断是否为入口；yes 后分别询问七类形成方式和一个用途问题 |
| 标签处理 | 保留模型原标签；无阈值纠正、规则代判或人工改写 |
| 范围 | application：按既有索引的业务路径范围，包含其中内嵌插件测试/迁移，不含仓库根 tests/migrations |
| 文件 / 物理行 / 有函数的文件 | 185 / 23,156 / 154 |
| 上下文预算 | 直接使用位置最多 6；接收类最多 12；绑定证据最多 24 |
| 有绑定证据 / 继承接收类候选的函数 | 413 / 51 |
| 目标函数本体 | 847 个全部完整保留；绑定证据超过预算会记录省略 |
| Ground truth | 本次按用户指定采用 ctfd-application-v1 静态参考标注 |

**2. 数据分布**

| 项目 | 数量 |
|---|---:|
| 全部目标函数 | 847 |
| GT 入口 | 392 |
| GT 非入口 | 413 |
| GT 不确定（不计分） | 42 |
| Jev 判断入口 | 256 |
| Jev 判断非入口 | 590 |
| Jev 判断不确定 | 1 |
| 成功取得流程结果 | 847 |
| 最终请求失败 / 未执行函数 | 0 / 0 |
| GT 确定的计分范围 | 805 |
| 模型明确 yes/no 的计分范围 | 804 |

GT 不确定的 42 项中，模型判 yes 2 项、no 40 项，均不进入正确/错误计分。因此被计分的模型正例为 254，而非 256。

**3. 入口识别混淆矩阵**

| GT / Jev | 入口 | 非入口 | 不确定 |
|---|---:|---:|---:|
| 入口 | 253（TP） | 138（FN） | 1 |
| 非入口 | 1（FP） | 412（TN） | 0 |

**4. 入口识别指标**

| 指标 | 计算 | 结果 |
|---|---|---:|
| 精确率 | 253 / (253+1) | 99.61% |
| 全正例召回率 | 253 / 392 | 64.54% |
| F1（全正例召回口径） | 上述 P、R 的调和平均 | 78.33% |
| 确定回答召回率 | 253 / (253+138) | 64.71% |
| 确定回答 F1 | 2TP / (2TP+FP+FN) | 78.45% |
| 确定回答准确率 | (253+412) / 804 | 82.71% |
| 全部确定真值的正确比例 | (253+412) / 805 | 82.61% |
| 负例误报率 | 1 / 413 | 0.24% |

模型 unknown 单独保留。全正例召回率把它算作尚未识别出的入口，但不将其伪装为一个明确 no。

**5. 按主用途的识别召回**

| 主用途 | GT 入口 | 找到 | 明确漏报 | 模型不确定 | 召回率 |
|---|---:|---:|---:|---:|---:|
| http | 225 | 224 | 1 | 0 | 99.56% |
| cli | 6 | 6 | 0 | 0 | 100.00% |
| lifecycle | 28 | 17 | 11 | 0 | 60.71% |
| event | 6 | 2 | 4 | 0 | 33.33% |
| other | 127 | 4 | 122 | 1 | 3.15% |

该表评价是否识别为入口，不要求模型用途标签也正确。other 主要包括模板回调、序列化/校验钩子、配置策略和插件方法。

**6. GT 的形成方式分布**

| 形成方式 | GT 支持函数数 |
|---|---:|
| registration | 34 |
| inheritance | 201 |
| interface_implementation | 20 |
| configuration | 94 |
| callback | 127 |
| decorator | 256 |
| other | 1 |

形成方式是多标签，同一函数可同时属于多类，各行不能相加作为函数总数。

**7. 入口识别正确后，分类是否正确**

仅对 253 个 TP 评价，避免与识别漏报混淆。

| 指标 | 数量 | 比例 |
|---|---:|---:|
| 形成方式完全一致 | 1 / 253 | 0.40% |
| 形成方式不完全一致 | 252 / 253 | 99.60% |
| 用途匹配 | 242 / 253 | 95.65% |
| 用途不匹配（含 unknown/none） | 11 / 253 | 4.35% |
| 形成方式和用途同时匹配 | 1 / 253 | 0.40% |

多标签统计：标签 TP=403、FP=460、FN=26；micro Precision=46.70%，Recall=93.94%，F1=62.38%。

| 形成方式 | TP 内 GT 支持 | 标签 TP | 多选 FP | 未命中 FN | unknown | P | R | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| registration | 3 | 3 | 238 | 0 | 0 | 1.24% | 100.00% | 2.46% |
| inheritance | 162 | 146 | 0 | 16 | 0 | 100.00% | 90.12% | 94.81% |
| interface_implementation | 2 | 2 | 7 | 0 | 0 | 22.22% | 100.00% | 36.36% |
| configuration | 9 | 1 | 200 | 8 | 6 | 0.50% | 11.11% | 0.95% |
| callback | 18 | 17 | 15 | 1 | 0 | 53.12% | 94.44% | 68.00% |
| decorator | 234 | 234 | 0 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| other | 1 | 0 | 0 | 1 | 0 | n/a | 0.00% | 0.00% |

形成方式完全匹配要求所有标签一致，任一标签回答 unknown 不计完全正确。configuration 的 6 个 unknown 单独列出，不当作明确 no。

**8. 端到端分类：包含入口漏报和误报的影响**

| 指标 | 结果 |
|---|---:|
| 入口识别且形成方式完全匹配 | 1 / 392 = 0.26% |
| 入口识别且用途匹配 | 242 / 392 = 61.73% |
| 形成方式标签 TP / FP / FN | 403 / 462 / 330 |
| 形成方式 micro Precision | 46.59% |
| 形成方式 micro Recall | 54.98% |
| 形成方式 micro F1 | 50.44% |

未找到的真实入口，其标签属于未恢复标签；真实非入口上预测出的形成方式属于额外标签。GT 不确定项仍排除。

| 形成方式 | 全部 GT 支持 | 标签 TP | FP | FN | P | R | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| registration | 34 | 3 | 239 | 31 | 1.24% | 8.82% | 2.17% |
| inheritance | 201 | 146 | 0 | 55 | 100.00% | 72.64% | 84.15% |
| interface_implementation | 20 | 2 | 7 | 18 | 22.22% | 10.00% | 13.79% |
| configuration | 94 | 1 | 201 | 93 | 0.50% | 1.06% | 0.68% |
| callback | 127 | 17 | 15 | 110 | 53.12% | 13.39% | 21.38% |
| decorator | 256 | 234 | 0 | 22 | 100.00% | 91.41% | 95.51% |
| other | 1 | 0 | 0 | 1 | n/a | 0.00% | 0.00% |

**9. 全部入口子类型识别统计**

子类型允许重叠，各行不直接相加。

| 子类型 | GT 入口 | 找到 | 明确漏报 | 未决 | 召回率 |
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

**10. 特殊样本**

- 唯一误报：CTFd.utils.csv.dump_scoreboard_csv。GT 为内部辅助函数，Jev 判 HTTP 入口。
- 唯一模型不确定：CTFd.utils.social.SolveSocialShare.asset。GT 为配置选择的分享策略入口。
- 唯一 HTTP 相关漏报：CTFd.events.subscribe.gen，SSE 流式响应体生成器。
- 形成方式完全匹配的唯一 TP：CTFd.plugins.register_plugin_assets_directory.assets_handler。
- 普通 Flask 路由 66/66、RESTX Resource 方法 155/155、注册资源处理函数 2/2 均被识别。

**11. 扫描运行与 Jev 用量**

下表是产生这批预测的扫描耗时，不含 UAST 导出、上下文准备、离线标注/评估和运行之间的等待时间。

| 扫描运行 | 状态 | 本次处理函数（含失败） | 复用成功函数 | 耗时 |
|---|---|---:|---:|---|
| 1 | interrupted | 479 | 0 | 56m3s342ms |
| 2 | finished_with_errors | 652 | 195 | 28m53s586ms |
| 3 | completed | 86 | 761 | 5m47s442ms |

各次处理数含重试，不相加作为独立函数数量。

| 累计项目 | 数量 |
|---|---:|
| 已记录 run 耗时合计 | 90m44s370ms |
| 真实 API 请求尝试 | 3,266 |
| 成功响应 | 2,895 |
| HTTP 错误响应 | 0 |
| 连接失败尝试 | 371 |
| 输入 token | 2,862,666 |
| 输出 token | 128,018 |
| 合计 token | 2,990,684 |
| 平均请求耗时（含失败） | 1640.53ms |
| 请求耗时 70% / 99% / 100% | 932.84ms / 6143.92ms / 180235.08ms |

成功响应数符合：256×9 + 590×1 + 1×1 = 2,895。yes 函数请求入口判断和八个分类问题；no/unknown 仅请求入口判断。
这些用量来自成功回复的 usage；没有回复的连接失败没有可核实的 token 数据，不估算其费用。离线评估没有调用 API。

**12. 实验记录措辞**

按本次选定的 CTFd ground truth，Jev 在精简上下文下的入口识别精确率为 99.61%，全正例召回率为 64.54%，F1 为 78.33%。
它覆盖全部普通 Flask 路由和 RESTX Resource 方法；漏报主要位于模板回调与框架/插件扩展边界。
在 253 个正确识别的入口中，用途分类匹配率为 95.65%，形成方式完全匹配率为 0.40%；后者主要受 registration、configuration 多选影响。
以上结论只针对该仓库、冻结输入和当前 GT 分类边界，不能单凭这些数字确定漏报由模型、提示词还是上下文缺失造成。

原始来源：[REPORT.md](REPORT.md)、[metrics.json](metrics.json)、[manifest.json](manifest.json)、冻结的 ground-truth / predictions 快照。
