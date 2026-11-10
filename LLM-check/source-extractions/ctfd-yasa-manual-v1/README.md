# CTFd 漏洞报告 source 提取

仅提取报告中明确标记 SOURCE 的步骤，未运行 YASA 或调用模型。

输入：`/data/fyn/yasa/YASA-Engine/artifacts/ctfd-yasa-manual/report/report.sarif`。告警 54 条，source 出现 54 次，按源码位置和表达式去重后 16 个。

- [sources.csv](sources.csv)：去重 source 表，可用 Excel 打开。
- [sources.json](sources.json)：完整位置、源码、所属函数及关联记录。
- [source-finding-links.csv](source-finding-links.csv)：source、报告入口和告警/sink 的关联。
- [source-occurrences.json](source-occurrences.json)：每次出现的 SARIF 精确索引和原始位置。
- [findings.json](findings.json)：每条告警的入口、sink 与 source ID。

## 去重来源

| 文件位置 | 所属函数 | 报告中的来源表达式 | 关联告警数 |
|---|---|---|---:|
| [CTFd/__init__.py:212](/data/fyn/yasa/YASA-Engine/CTFd/CTFd/__init__.py:212) | CTFd.create_app | `app.config.get(THEME_FALLBACK)` | 1 |
| [CTFd/__init__.py:290](/data/fyn/yasa/YASA-Engine/CTFd/CTFd/__init__.py:290) | CTFd.create_app | `app.config.get(REVERSE_PROXY)` | 2 |
| [CTFd/admin/__init__.py:81](/data/fyn/yasa/YASA-Engine/CTFd/CTFd/admin/__init__.py:81) | CTFd.admin.plugin | `plugin` | 3 |
| [CTFd/api/v1/challenges.py:321](/data/fyn/yasa/YASA-Engine/CTFd/CTFd/api/v1/challenges.py:321) | CTFd.api.v1.challenges.ChallengeTypes.get | `CHALLENGE_CLASSES.get(class_id)` | 2 |
| [CTFd/api/v1/challenges.py:349](/data/fyn/yasa/YASA-Engine/CTFd/CTFd/api/v1/challenges.py:349) | CTFd.api.v1.challenges.Challenge.get | `challenge_id` | 16 |
| [CTFd/api/v1/challenges.py:507](/data/fyn/yasa/YASA-Engine/CTFd/CTFd/api/v1/challenges.py:507) | CTFd.api.v1.challenges.Challenge.get | `challenge_id` | 8 |
| [CTFd/api/v1/scoreboard.py:35](/data/fyn/yasa/YASA-Engine/CTFd/CTFd/api/v1/scoreboard.py:35) | CTFd.api.v1.scoreboard.ScoreboardList.get | `db.session.execute(select({0:Users.id, 1:Users.name, 2:Users.oauth_id, 3:Users.team_id, 4:Users.hidden, 5:Users.banned, 6:Users.bracket_id, 7:Brackets.name.label(bracket_name)}).where(Users.team_id.isnot(...)).join(Brackets, Users.bracket_id==Brackets.id, var isouter:any=true))` | 1 |
| [CTFd/auth.py:587](/data/fyn/yasa/YASA-Engine/CTFd/CTFd/auth.py:587) | CTFd.auth.oauth_redirect | `headers` | 1 |
| [CTFd/plugins/challenges/__init__.py:358](/data/fyn/yasa/YASA-Engine/CTFd/CTFd/plugins/challenges/__init__.py:358) | CTFd.plugins.challenges.get_chal_class | `CHALLENGE_CLASSES.get(class_id)` | 7 |
| [CTFd/utils/__init__.py:46](/data/fyn/yasa/YASA-Engine/CTFd/CTFd/utils/__init__.py:46) | CTFd.utils._get_config | `db.session.execute(Configs.__table__.select().where(Configs.key==key))` | 1 |
| [CTFd/utils/__init__.py:79](/data/fyn/yasa/YASA-Engine/CTFd/CTFd/utils/__init__.py:79) | CTFd.utils.get_config | `DEFAULTS.get(key)` | 6 |
| [CTFd/utils/config/pages.py:70](/data/fyn/yasa/YASA-Engine/CTFd/CTFd/utils/config/pages.py:70) | CTFd.utils.config.pages.get_page | `db.session.execute(Pages.__table__.select().where(Pages.route==route).where(Pages.draft.isnot(true)))` | 1 |
| [CTFd/utils/exports/databases.py:8](/data/fyn/yasa/YASA-Engine/CTFd/CTFd/utils/exports/databases.py:8) | CTFd.utils.exports.databases.is_database_mariadb | `db.session.execute(SELECT version())` | 1 |
| [CTFd/utils/initialization/__init__.py:207](/data/fyn/yasa/YASA-Engine/CTFd/CTFd/utils/initialization/__init__.py:207) | CTFd.utils.initialization.init_request_processors | `app.config.get(APPLICATION_ROOT)` | 1 |
| [CTFd/utils/migrations/__init__.py:20](/data/fyn/yasa/YASA-Engine/CTFd/CTFd/utils/migrations/__init__.py:20) | CTFd.utils.migrations.create_database | `url.set(var drivername:any=postgresql)` | 2 |
| [CTFd/utils/updates/__init__.py:58](/data/fyn/yasa/YASA-Engine/CTFd/CTFd/utils/updates/__init__.py:58) | CTFd.utils.updates.update_check | `requests.get(https://versioning.ctfd.io/check, var params:any=params, var timeout:any=3)` | 1 |

## 使用边界

这些是 YASA 在已输出告警路径中标记的来源，不是全仓 source 清单，也不是人工确认的外部输入真值。配置/数据库读取等记录原样保留，不按人工语义过滤。
同一来源可以关联多个入口和告警。报告入口可能缺少类名和定义行号，因此 descriptor 数不能当成精确去重的函数数；尤其不要合并同名 get 方法为同一个真实函数。
源码片段和所属函数从当前本地源码补充；不擅自宣称已经证明历史扫描与当前 commit 一致。原始报告片段、位置和 nodehash 均保留。
source 的污点标签及原始匹配规则未保存在这份 SARIF 中，相关字段保留 null。告警索引采用 SARIF 原始的零起始索引。

重现命令（在 YASA-Engine 下执行）：

```bash
PYTHONDONTWRITEBYTECODE=1 /data/fyn/conda_envs/laya/bin/python -B LLM-check/extract_report_sources.py \
  --report /data/fyn/yasa/YASA-Engine/artifacts/ctfd-yasa-manual/report/report.sarif --repo /data/fyn/yasa/YASA-Engine/CTFd --out LLM-check/source-extractions/ctfd-yasa-manual-v1
```

再次执行时请将 `--out` 指向新的目录；脚本会拒绝覆盖已有提取结果。完整性检查及 65 项离线测试通过，见 verification.json。
