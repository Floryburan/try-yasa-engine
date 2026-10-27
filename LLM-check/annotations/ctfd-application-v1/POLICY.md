# CTFd 函数级入口参考标注 v1

本数据集覆盖既有业务扫描范围中的全部 847 个普通函数、方法和嵌套函数，来源为
CTFd commit `a751d1773df7f16341801831481eeb7b1ded18c2`。它是 Codex 基于源码制作的
静态参考标注，不是独立人工专家金标准。所有条目需要后续独立复核；证据不足的条目保留 unknown。
标注构建程序不读取 Jev/Laya 预测、模型置信度或 YASA checker 的入口结果，不调用模型 API。

## 判定单位与边界

- 一个源码定义是一个目标，以文件、作用域、定义起止位置和原始函数 ID 识别。
- 采用逻辑处理函数口径：已注册路由的原始处理函数为正例，装饰器工厂和共享 wrapper 定义不重复计为入口。
- 正例包括：HTTP 处理函数、CLI 命令、Flask 请求/响应/URL 钩子、事件/后台执行器任务、
  显式配置的模板函数/模板命名空间成员，以及实际注册并由框架或 CTFd 扩展调度器调用的扩展接口。
- CTFd 插件加载器、题目/flag/provider/uploader 的配置选择和接口调度列入扩展入口，单独记录 subtype；
  不能把这些函数全部解释为独立 HTTP endpoint。仅被插件方法直接调用的内部辅助函数仍为负例。
- 普通数据库模型的构造、property/hybrid_property、repr/迭代等语言协议，以及普通工具函数，
  不因 Python/ORM 能间接调用它们而自动成为入口。显式注册的框架校验钩子除外。
- 对有 Schema.Meta.model 显式绑定的自定义模型构造器，记录 Marshmallow 可能间接构造的证据，
  保留 unknown 作为数据对象构造的口径边界，不能用普通构造器的负例规则覆盖这类路径。
- 内部工具库的 predicate/编码器/容器更新回调存在口径边界，无法可靠归入应用入口的保留 unknown，
  不把“是回调”直接等同于“是应用入口”。
- 只判断仓库自带代码和可确认配置下的潜在入口；条件启用的插件/SQLite/主题等写 activation 条件，
  不声称在同一次实际部署中全部启用。没有运行应用、连接数据库或枚举运行时真实请求。
- `CTFd/` 下内嵌的测试/迁移文件仍属于原扫描的 847 个目标。测试运行器函数不是部署应用入口；
  插件迁移中源码加载器实际调用的 upgrade 为扩展生命周期入口，未确认调用链的 downgrade 保留 unknown。
- 当前范围不含仓库根 tests、migrations、其他脚本、20 个 lambda、解析器生成函数或模块顶层执行。

## 保留的输出标签

`is_entrypoint` 为 true / false / null；null 表示证据不足，不能折算为负例。

形成方式为可重叠标签，但每一个标签必须有独立的源码依据：

| 标签 | 标注约定 |
|---|---|
| registration | 目标可调用对象明确传入注册 API，如 add_url_rule(view_func=...)、注册错误处理函数、模板 globals.update |
| inheritance | 已绑定/注册的具体类型继承框架或扩展基类，目标属于其调度方法，或者实现由注册子类继承 |
| interface_implementation | 存在明确的扩展方法契约/抽象约定，如 SessionInterface、CSRF、Uploader/EmailProvider；仅继承 Resource 不自动加此标签 |
| configuration | 目标/承载类型由命名配置槽或显式映射选择，如 request_class、session_interface、filters 字典、provider registry |
| callback | 已提交给生命周期/事件/模板/校验/扩展调度器的回调；普通 HTTP 路由不自动加 callback |
| decorator | 装饰器负责绑定目标或其承载 Resource 类；普通 wraps、cache、classmethod、property 本身不算入口绑定证据 |
| other | 以上机制以外的发现约定，必须解释，例如独立的应用 factory；不与六类已知机制混用 |

装饰器内部隐含的注册行为不额外标 registration，路由路径/装饰器参数本身不额外标 configuration。
因此 @views.route 的形成方式通常只有 decorator；实际 Resource.get 标 inheritance + decorator。
配置字典赋值与注册 API 调用分别标 configuration 和 registration，避免同一证据无限扩张标签。
插件 load/迁移 upgrade 的命名发现约定保存在 subtype，但主要形成方式标 callback，不再叠加 other。

用途保留 http / rpc / cli / event / lifecycle / other；非入口 entrypoint_kind=null。
同时具有多种触发用途时保留 entrypoint_kinds 全集，entrypoint_kind 为展示用主用途。
unknown 条目另存 candidate_formation_types，不能拿这些候选当成确定标签。

## 证据与评测限制

每条标注保存完整目标源码、源码哈希、分类理由、证据代码和文件行号。
正例至少有一处注册/配置/调度证据；负例说明内部调用或非入口角色，并在可解析时附直接调用者。
静态未找到注册不能单独证明运行时永远不可能注册，尤其是外部插件、反射和用户自定义主题。
这是按明确边界制作的参考集；不能将构建脚本的批量归类冒充独立人工逐条复核。
正式论文/最终效果评估前，应由未看模型预测的第二位标注者逐条复核，重点检查负例和边界条目。

## 框架契约参考

- [Flask API](https://flask.palletsprojects.com/en/2.1.x/api/)：request_class、session_interface、请求钩子和注册 API。
- [Jinja API](https://jinja.palletsprojects.com/en/stable/api/)：filters/globals 和 Loader.get_source 扩展点。
- [Marshmallow 2 API](https://marshmallow.readthedocs.io/en/2.x-line/api_reference.html)：pre_load/post_dump 和校验器。
- [WTForms CSRF](https://wtforms.readthedocs.io/en/2.3.x/csrf/)：csrf_class 和 generate_csrf_token。

上述文档说明调度契约；每个具体目标是否绑定，仍以冻结的仓库源码为证据。
