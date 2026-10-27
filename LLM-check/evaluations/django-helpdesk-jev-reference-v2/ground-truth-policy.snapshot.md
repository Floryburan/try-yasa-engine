# django-helpdesk 入口参考标注口径 v1

本集是 AI 辅助的静态源码参考标注，作为当前实验 ground truth 使用；不是独立人工审定真值。构建过程不读取 Jev/Laya 预测、不调用模型 API，不运行 Django app、管理命令、迁移或数据库。

## 冻结对象与范围

- 仓库：django-helpdesk，commit `8c7b9ff92f018a394c6faa972e4328ad178b80b9`，版本 2.6.1。
- 按 pyproject.toml 的源码打包配置选择 `src/helpdesk/`，import root 为 `src`，而非沿用 CTFd 顶层目录名规则。
- 包内全部 `def` / `async def`，包括方法、嵌套函数和迁移函数；同一个源码定义只有一条记录，多个 URL/接收类绑定合并到 bindings。
- 包内迁移单列 `scope_partition=migrations`，其余为 `runtime_application`。后续只评估日常业务时选择后者；不得混用分母。
- 排除 tests、demodesk、dockerized、docs 和根目录脚本的目标定义；这些文件仍可提供部署/注册证据，排除不等于不可能有漏洞。
- 不纳入 lambda、解析器生成函数、模块顶层代码、第三方依赖中没有本地定义的处理函数。外部 Django 认证视图等记录到 dispatch_inventory，但不伪造本地函数标签。
- 参考集面向可安装 Django app，条件是宿主将 helpdesk 加入 INSTALLED_APPS 并 include(helpdesk.urls)。按源码中可启用的分支标注，不声称所有部署默认启用所有入口。

## 什么算入口

沿用 CTFd 的广义应用调度边界：框架/事件/模板/任务/CLI/明确配置扩展机制选择的本地逻辑函数。既含 HTTP 处理，也含已绑定的框架回调；回调数量不能当成独立 HTTP URL 数量。

正例需要具体的本地绑定证据和对应框架契约。不能仅凭名字、继承、装饰器存在或“没有调用者”判正。普通辅助函数不会因入口调用它而成为入口；函数负责注册别的 handler，也不自动成为入口。

- `path/re_path` 绑定的本地函数是 HTTP 入口；普通鉴权、csrf、wraps 装饰器不额外产生 decorator 形成标签。
- `as_view()` / DRF router 绑定具体类后，实际执行的 HTTP 方法和已覆盖的框架调度钩子算入口；本地基类中被使用的同一实现按定义合并，记录具体接收类。普通 get_next_url / accessible_followups 不算框架钩子。
- 本快照涉及的基类钩子链经过源码核对，覆盖方法中需要的 super 链仍执行；此构建器不是通用 Python MRO/反射分析器。修改继承链后应重新审阅。
- 绑定到 URLconf 的 Feed 对象，其文档规定的 get_object/items/元数据方法属于框架回调。
- AppConfig.ready、BaseCommand.handle/add_arguments、Django signal receiver、Celery shared_task、模板 Library 注册函数均纳入；启动/命令/任务内的普通被调函数不自动纳入。
- 注册后台的 ModelAdmin.list_display 方法、delete_queryset；已安装具体模型的 save、后台 delete、ModelForm 触发的 clean、后台 view-on-site 的 get_absolute_url；已配置 Manager.get_queryset 纳入。一般模型查询方法/属性不纳入。
- 具体附件实现的 attachment_path 实现显式基类契约，且由 FileField.upload_to 桥接回调调度；抽象占位实现判负。
- callable 字段 default/upload_to/validators、命名可替换 settings 回调槽、已使用的表单 clean/clean_<field>、DRF SerializerMethodField/create/update/validate 纳入。`default=fn()` 不等同于 `default=fn`。
- Markdown extensions 选择的 extendMarkdown 纳入；普通 markdown 转换调用的 get_markdown 函数不因此变成入口。
- user_passes_test 收到的最终用户谓词纳入；返回它的工厂、共享装饰器 wrapper 按逻辑函数边界判负。
- RunPython 正向、反向（包括 noop）都是迁移回调；pickle/fixture 内部工具判负。迁移文件字段引用的现存 callable 可能同时有 lifecycle 和 other 用途，保留 entrypoint_kinds 全集。
- get_email 模块还保留 `__main__` 直接选择 process_email 的脚本分支，作为 CLI 主逻辑按 other 形成机制标注，条件是宿主已准备 Django 环境/应用初始化；不把 process_email 的其余被调函数也当成脚本入口。
- str/property 等普通语言/数据对象协议不因隐式访问而无限扩张为应用入口。普通模型属性在模板使用，也不等于模板命名空间注册。
- 框架通过配置选择的表单/serializer 构造器与其 super 初始化，沿用 CTFd 组件构造边界，标为 unknown；不当成确定负例计分。项目显式构造的其他普通对象构造器判负。

## 形成方式与用途

形成方式多选，标签与 CTFd/Jev 保持一致：

| 标签 | 本集解释 |
|---|---|
| registration | 显式绑定 API，如 URL path/re_path、as_view、router.register、signal.connect、Library.filter、RunPython |
| inheritance | 已绑定具体接收类上的框架覆盖方法或实际使用的继承实现；继承本身不够 |
| interface_implementation | 实现有明确抽象/协议声明的方法契约；本集是 Attachment.attachment_path，不将所有 Django 覆盖方法都加此标签 |
| configuration | 命名配置槽、字段 callable、serializer_class / SerializerMethodField、list_display 等选择目标/承载类型 |
| callback | 生命周期/事件/模板/校验/扩展机制回调；普通 HTTP 路由不自动添加 |
| decorator | 装饰器负责绑定目标或承载类，如 receiver/shared_task/Library/admin.register；admin.display、wraps、csrf_exempt 仅自身不够 |
| other | 六类以外的形成机制，需要解释；不得与已知机制混用 |

装饰器内隐含注册不重复标 registration；URL 字符串或普通装饰器参数不等于 configuration。承载类的 admin.register 证据可产生 decorator，admin.display 本身只是显示元数据。

用途固定为 http / rpc / cli / event / lifecycle / other，与形成方式是并列维度。CBV/Feed 请求调度方法为 http；通用模板/serializer/ORM/权限回调为 other；信号和 Celery 消息任务为 event；应用 ready 和迁移为 lifecycle。用途不是“是否接收不可信输入”的判断。

`is_entrypoint` 为 true / false / null；true 的 formation_types 是完整多选集合；false/null 的 formation_types 为空，null 的候选标签放 candidate_formation_types。空类别是合法的实测结果，不人为补齐每一类的样本。

## 证据、完整性和评测

每条保存函数身份、case_id、完整目标源码证据、SHA256、形成方式/用途/子类型、理由、绑定位置和条件。manifest 锁定仓库版本、源码、UAST 索引、构建器、政策和标注哈希。

“完整”指本次包范围的每个源码函数都被覆盖，不保证静态分析能证明所有动态注册。负例是在此版本和明确边界下的源码角色判断，不是运行时不可达证明；所有记录保留 needs_independent_review=true。

已知 true/false 可作当前二分类评测；unknown 单列、不当负例。形成方式应同时报告逐标签指标和完整集合 exact match；不能用“多选命中一个标签”替代整组正确。按函数身份去重后计数，不按 URL 数或接收类数重复计数。

## 框架契约

具体绑定以本地冻结源码为准，以下官方资料说明回调契约：

- [Django 5.2 CBV](https://docs.djangoproject.com/en/5.2/ref/class-based-views/base/) 与 [编辑视图](https://docs.djangoproject.com/en/5.2/ref/class-based-views/generic-editing/)。
- [AppConfig.ready](https://docs.djangoproject.com/en/5.2/ref/applications/#django.apps.AppConfig.ready)。
- [管理命令](https://docs.djangoproject.com/en/5.2/howto/custom-management-commands/)。
- [信号注册](https://docs.djangoproject.com/en/5.2/topics/signals/#connecting-receiver-functions)。
- [模板 Library](https://docs.djangoproject.com/en/5.2/howto/custom-template-tags/)。
- [Admin](https://docs.djangoproject.com/en/5.2/ref/contrib/admin/) 的 list_display、delete_queryset、view_on_site。
- [模型实例方法](https://docs.djangoproject.com/en/5.2/ref/models/instances/)、[字段 callable](https://docs.djangoproject.com/en/5.2/ref/models/fields/)、[表单校验](https://docs.djangoproject.com/en/5.2/ref/forms/validation/)。
- [RunPython](https://docs.djangoproject.com/en/5.2/ref/migration-operations/#runpython)、[Feed](https://docs.djangoproject.com/en/5.2/ref/contrib/syndication/)。
- [DRF 泛型视图](https://www.django-rest-framework.org/api-guide/generic-views/)、[ViewSets](https://www.django-rest-framework.org/api-guide/viewsets/)、[Serializers](https://www.django-rest-framework.org/api-guide/serializers/)、[SerializerMethodField](https://www.django-rest-framework.org/api-guide/fields/#serializermethodfield)。
- [Celery shared_task](https://docs.celeryq.dev/en/stable/django/first-steps-with-django.html#using-the-shared-task-decorator)。
- [Python Markdown 扩展 API](https://python-markdown.github.io/extensions/api/#extendmarkdown)。
