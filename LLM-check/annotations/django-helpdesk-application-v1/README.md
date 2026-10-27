# django-helpdesk ground truth v1

按当前实验约定，把 AI 辅助静态参考标注作为 ground truth。没有读取 Jev/Laya 预测，没有调用 API，尚未经独立人工复核。

冻结仓库：`django-helpdesk` 2.6.1，commit `8c7b9ff92f018a394c6faa972e4328ad178b80b9`。详细边界见 [POLICY.md](POLICY.md)。

## 可以直接记录的统计

| 范围 | Python 文件 | 函数定义 | 入口 | 非入口 | 不确定 |
|---|---:|---:|---:|---:|---:|
| 安装包 src/helpdesk 全部 | 92 | 425 | 203 | 218 | 4 |
| 日常应用代码（排除 migrations） | 48 | 409 | 190 | 215 | 4 |
| 迁移代码 | 44 | 16 | 13 | 3 | 0 |

包内物理源码共 14,598 行，包含空行和注释。48 个文件含函数定义，其他包文件主要是空初始化文件或声明式迁移文件。

全仓库 UAST 覆盖 172 个 Python 文件、1,103 个源码函数定义。另有 20 个 lambda 和 1 个解析器生成函数，不纳入本集。排除的 tests 为 64 文件/674 函数；示例、部署、文档和根脚本共 16 文件/4 函数。排除表示本实验范围选择，不表示这些代码一定安全。

## 如何打开

| 文件 | 内容 |
|---|---|
| [annotations.csv](annotations.csv) | Excel 可直接打开的完整逐函数表，UTF-8 BOM |
| [annotations.json](annotations.json) | JSON 数组，每个函数一条；完整目标源码、绑定证据、哈希和分类 |
| [annotations.jsonl](annotations.jsonl) | 与 JSON 相同，一行一条，适合脚本读取 |
| [entrypoints.csv](entrypoints.csv) | 203 个确定入口 |
| [non-entrypoints.csv](non-entrypoints.csv) | 218 个非入口 |
| [uncertain.csv](uncertain.csv) | 4 个边界构造器 |
| [runtime-application.csv](runtime-application.csv) | 排除迁移的 409 个日常应用函数 |
| [migrations.csv](migrations.csv) | 16 个迁移函数 |
| [ANNOTATIONS.md](ANNOTATIONS.md) | 按入口/不确定/非入口分组的阅读表，源码链接可点击 |
| [FILE_COVERAGE.md](FILE_COVERAGE.md) | 全仓库文件清单、范围和函数覆盖 |
| [dispatch_inventory.json](dispatch_inventory.json) | 每个 URL/router/as_view 绑定的目标定义、外部实现分类、条件分支 |
| [summary.json](summary.json) | 类别和范围统计 |
| [manifest.json](manifest.json) | 仓库版本、索引/源码/标注/政策/构建器的哈希 |
| [verification.json](verification.json) | 覆盖、证据和离线测试核验记录 |

## 保存结构

`annotations.json` 是数组，不是按 URL 组织的字典。核心字段与 CTFd 一致：

```json
{
  "function": "helpdesk.views.staff.dashboard",
  "file": "src/helpdesk/views/staff.py",
  "start_line": 184,
  "is_entrypoint": true,
  "formation_types": ["registration"],
  "entrypoint_kind": "http",
  "entrypoint_kinds": ["http"],
  "subtypes": ["django_url_function"],
  "scope_partition": "runtime_application"
}
```

上例仅展示核心字段。实际记录还有 function_id、case_id、definition_identity、完整源码 evidence、bindings、理由、激活条件、source_sha256 和复核状态。同一函数的多个 URL、条件绑定或接收类保存在同一条的 bindings 中，不重复增加函数数。

`is_entrypoint` 为 `true`、`false`、`null`。null 的候选形成方式存 candidate_formation_types；不把它混入确定正负例。

## 类型统计

用途统计按主用途 entrypoint_kind，每个确定入口计一次：

| 主用途 | 函数 |
|---|---:|
| http | 103 |
| cli | 10 |
| event | 4 |
| lifecycle | 24 |
| other | 62 |
| rpc | 0 |

其中 HTTP 103 包括 URL 函数 46、CBV 钩子 28、DRF ViewSet 钩子 9、Feed 方法 20，**不等于 103 个独立 HTTP URL**。24 个 lifecycle 包括迁移回调，以及同时被历史迁移字段配置引用的 callable；它们可同时有 other 用途。完整用途集合中 other 有 72 个，不能与主用途 62 混用。

形成方式是多选，各列之和可以超过 203：

| 形成方式 | 函数 |
|---|---:|
| registration | 122 |
| inheritance | 104 |
| interface_implementation | 2 |
| configuration | 40 |
| callback | 149 |
| decorator | 17 |
| other | 1 |

入口举例：URL 的 dashboard；继承/框架调度的 TicketViewSet.get_queryset；实现 Attachment 契约的 FollowUpAttachment.attachment_path；配置选择的字段默认值/校验器；信号 receiver；Celery shared_task；命令 handle/add_arguments；模板 filter；迁移 RunPython。

普通辅助函数如 ViewTicket.get_next_url、FollowUpAttachmentViewSet.accessible_followups、notify_followup_webhooks、process_queue 均为非入口。其调用者可能是入口，不转移身份。

不确定的四个函数是 AbstractTicketForm.__init__、TicketForm.__init__、PublicTicketForm.__init__、BaseTicketSerializer.__init__。沿用 CTFd 对框架选择的组件构造器/父级初始化的边界处理。

## 重建与使用

从 `/data/fyn/yasa/YASA-Engine` 执行，使用现有 Laya Python 环境；本脚本只依赖标准库：

```bash
PYTHONDONTWRITEBYTECODE=1 /data/fyn/conda_envs/laya/bin/python -B \
  LLM-check/build_helpdesk_reference.py

PYTHONDONTWRITEBYTECODE=1 /data/fyn/conda_envs/laya/bin/python -B \
  -m unittest discover -s LLM-check -p 'test_helpdesk_reference.py' -v
```

构建器锁定此 commit 和索引根配置；换版本需要重新审阅、建立新版本目录。输入索引位于 `artifacts/django-helpdesk-uast/index`，生成命令和解析核验见该目录上级的 provenance.json。

本次未运行 Jev。后续模型必须使用同一索引以保持 case_id/definition_identity 一致；425 全包或 409 日常应用范围应明确选择。二分类只对已知 true/false 评分，4 个 unknown 单列；形成方式报告逐标签指标和完整集合 exact match。
