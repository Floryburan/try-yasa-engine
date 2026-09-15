/* eslint-disable import/no-commonjs, import/no-import-module-exports,
  max-classes-per-file, jsdoc/require-jsdoc, jsdoc/require-param, jsdoc/require-returns,
  complexity, sonarjs/cognitive-complexity, no-nested-ternary,
  @typescript-eslint/no-loop-func, @typescript-eslint/no-use-before-define,
  sonarjs/no-duplicate-string */

import type {
  FrameworkCandidateCondition,
  FrameworkCandidateFilter,
  FrameworkEntryPointOperatorStep,
  FrameworkEntryPointPlan,
  FrameworkMatchCondition,
  FrameworkRuleAction,
  FrameworkRuleMatch,
  FrameworkSemanticRule,
  FrameworkSpec,
  FrameworkTrigger,
} from './framework-modeler'

const Checker = require('../common/checker')
const completeEntryPoint = require('../taint/common-kit/entry-points-util')
const { markTaintSource, getMarkedSourceCount } = require('../taint/common-kit/source-util')
const AstUtil = require('../../util/ast-util')
const logger = require('../../util/logger')(__filename)

/*
 * EntryPoint Operator Library — Phase 1，2026-09-13
 *
 * 阅读顺序：本设计记录 → public types → GenericEntryPointOperators → 原有 GenericFrameworkChecker。
 * 本轮只建立算子库，不修改旧 Spec、不新增 DSL、不迁移硬编码 checker。
 * 库中的 handle 是本次分析内的不透明引用，不是可序列化 JSON，也不向上层暴露 value.value。
 *
 * IMPLEMENTATION INVENTORY（路径相对 src；同行花括号表示各个实际文件，不是虚构实现）
 * 每行顺序：实现/语言/知识 K → 通用操作 M → 注册。taint/callchain 文件名同时标识 checker。
 * T = checker/taint；A = engine/analyzer；C = checker/callchain。
 * EP = common/entrypoint/entrypoint；complete = T/common-kit/entry-points-util。
 *
 * Python：
 * A/python/common/entrypoint-collector/python-entrypoint.ts：聚合以下 collector；模块函数索引 → taint 解析注册。
 * A/python/flask/entrypoint-collector/flask-default-entrypoint.ts：装饰器/基类/方法表 K；
 *   递归定义、继承图、元数据过滤 M → EP(file/name/loc) 描述符。
 * A/python/fastapi/entrypoint-collector/fastapi-entrypoint.ts：包/API/装饰器 K；
 *   导入别名、赋值产生的实例关联、装饰器筛选 M → EP 描述符；lifespan 执行另属状态建模。
 * A/python/mcp/entrypoint-collector/mcp-default-entrypoint.ts：装饰器名 K；扫描函数/元数据 M → EP 描述符。
 * A/python/gradio/entrypoint-collector/gradio-default-entrypoint.ts：组件/API/回调参数 K；
 *   导入证据、嵌套函数索引、位置/关键字参数、集合展开、名称关联 M → EP 描述符。
 * A/python/inference/entrypoint-collector/inference-default-entrypoint.ts：AiStudio/Triton 类/基类/方法名 K；
 *   类与方法筛选 M → 两个独立发现函数分别产生 EP 描述符。
 * A/python/httpserver/entrypoint-collector/httpserver-entrypoint.ts：handler/server 基类、方法名 K；
 *   跨文件继承、方法枚举、receiver/loc M → EP 描述符；findFilesWithHttpHandlers 返回文件候选。
 * A/python/tornado/entrypoint-collector/tornado-entrypoint.ts：基类/HTTP 方法/生命周期 K；
 *   继承、方法枚举、decorator 策略 M → EP 描述符；prepare 的 source 分析不属于入口算子。
 * A/python/agentuniverse/entrypoint-collector/agentuniverse-entrypoint.ts：依赖、配置键、基类/生命周期 K；
 *   读配置、模块限定类索引、关联、继承、方法定位 M → EP 描述符。
 * T/python/python-{default-taint-checker,taint-checker}.ts：配置与 collector 描述符 K；
 *   buildFclosIndex/lookupFclos、文件 UUID、重载/loc 匹配 M → analyzer.entryPoints；default 另有图/文件兜底。
 * T/python/django-taint-checker.ts：URLconf/include/as_view/路由参数 K；AST/符号解析、延迟关系、
 *   类方法枚举 M → complete → analyzer.entryPoints。
 * T/python/httpserver-taint-checker.ts：handler 类/方法 K；调用参数/返回值、类解包、去重 M → complete → entryPoints。
 * T/python/tornado-taint-checker.ts：路由结构/API/方法 K；union/集合展开、跨事件 WeakMap、类解析、
 *   方法筛选 M → complete → entryPoints；合成闭包/执行表达式是有副作用的补偿，不合入只读 resolve。
 * T/python/script-taint-checker.ts、skill-script-taint-checker.ts：脚本/skill 路径策略 K；
 *   文件候选筛选、UUID 解析 M → 文件入口 → entryPoints。
 *
 * Go：
 * A/golang/common/entrypoint-collector/go-default-entrypoint.ts + T/go/main-entrypoint-collect-checker.ts：
 *   main 名称 K；AstUtil.satisfy 符号扫描 M → complete → mainEntryPoints。
 * A/golang/gin/entrypoint-collector/gin-default-entrypoint.ts：API/receiver/Context 签名 K；
 *   类型/名称过滤、参数扫描、包装回调引用解析、位置去重 M → 闭包或 complete 结果。
 * T/go/gin-{default-taint-checker,taint-checker}.ts：Gin collector/配置 K；包成员定位、动态注册、
 *   签名/图兜底 M → entryPoints/ruleEntrypoints；两个版本收集和兜底策略不同。
 * T/go/go-default-taint-checker.ts：main/自定义配置 K；包/类/函数解析、调用图边界 M → mainEntryPoints。
 * T/go/beego-entrypoint-collect-checker.ts：路由/Controller/Filter/认证/错误回调 K；
 *   读参数/赋值、对象关系、遍历方法、解析控制字符串、创建实例/执行回调 M → complete → entryPoints。
 * T/go/cobra-command-checker.ts：Command action 字段 K；结构体/赋值/工厂返回 AST、闭包解析、
 *   位置去重 M → complete(isPreProcess=true) → mainEntryPoints。
 * T/go/urfave-cli-checker.ts：App.Action 字段 K；赋值目标/右值、闭包检查 M → complete → mainEntryPoints。
 * T/go/gRpc-entrypoint-collect-checker.ts：生成文件/Server 接口/注册参数 K；定义预处理、
 *   接口与注册函数关联、实现方法定位 M → complete → entryPoints。
 * T/go/gorilla-mux-entrypoint-collect-checker.ts：Router/API K；receiver 关联、回调参数/去重 M → complete → entryPoints。
 * T/go/restful-entrypoint-collect-checker.ts：WebService/API K；receiver 过滤、回调解析 M → complete → entryPoints。
 * T/go/go-cli-taint-checker.ts、go-http-taint-checker.ts：补 source，不独立发现入口。
 * T/go/sync-once-do-checker.ts：执行 Do 回调摘要，不直接注册 EP；不能混同外部入口发现。
 *
 * Java：
 * A/java/common/entrypoint-collector/java-default-entrypoint.ts：main 名称 K；package.members 扫描 M → 闭包。
 * A/java/spring/entrypoint-collector/spring-default-entrypoint.ts：注解名称 K；members 扫描、modifiers 过滤 M → 闭包。
 * T/java/java-{default-taint-checker,taint-checker}.ts：main/Spring/配置 K；包路径/符号解析 M → entryPoints；
 *   default 另有调用图和文件 helper。T/java/java-taint-abstract-checker.ts：重载消歧、接口实现、
 *   模拟 scope、参数对应关系 M → 交给上述 checker 注册；不是 Spring 专用知识。
 *
 * JavaScript（TypeScript 走 JS 路径，未发现独立 TS 入口发现器）：
 * A/javascript/egg/entrypoint-collector/egg-http.ts：路由 API、controller 路径/命名约定 K；
 *   AST 调用、末尾参数、字符串与文件关联、方法定位 M → 描述符 → T/js/egg-taint-checker.ts 注册。
 * T/js/js-taint-checker.ts、express/express-taint-checker.ts：配置 K；模块/导出查找、文件入口 M；
 *   JS 有图/文件兜底，Express 自动路由仍 TODO。T/js/source-util-for-egg.ts 是对象名称/source 适配。
 * T/js/nodejs-cli-taint-checker.ts：bin/scripts/shebang/路径证据 K；配置读取、文件定位 M → 文件入口。
 *
 * PHP：
 * A/php/sparta/entrypoint-collector/sparta-default-entrypoint.ts：Controller/方法排除/参数数 K；
 *   moduleScopes 类扫描、继承、方法筛选 M → EP 描述符。
 * A/php/soa/entrypoint-collector/soa-service-entrypoint.ts：Service 后缀/基类/参数数 K；
 *   继承、类成员直接取闭包 M → 完整 EP。
 * A/php/custom/entrypoint-collector/custom-mvc-controller-entrypoint.ts：Controller/可见性/签名 K；
 *   类筛选、modifiers/参数、成员解析 M → 完整 EP。
 * A/php/custom/entrypoint-collector/custom-databucket-entrypoint.ts：Bucket 命名/基类/签名 K；同上 M → 完整 EP。
 * T/php/php-default-taint-checker.ts：collector 优先级/自定义配置 K；context.funcs/moduleScopes 解析 M → entryPoints。
 *   图/文件兜底块实际被注释；没有从此处推断出配置路由发现。
 *
 * 跨语言和间接调用链：
 * C/go/go-callchain-checker.ts：main/配置 K；包符号/调用图 M → mainEntryPoints。
 * C/java/java-callchain-checker.ts：Spring/配置 K；collector/包/文件查找 M → entryPoints。
 * C/js/js-callchain-checker.ts：配置 K；getFclosFromScope/导出、调用图/文件 M → entryPoints。
 * C/python/python-callchain-checker.ts：Python 聚合 collector/配置 K；函数索引/文件 UUID M → entryPoints。
 * C/php/php-callchain-checker.ts：配置 K；函数定位/调用图 M → mainEntryPoints；调用文件 helper 不等于 helper 支持 PHP。
 * checker/common/full-callgraph-file-entrypoint.ts：图边界/位置/关键词/文件覆盖策略 K；
 *   图反向遍历、astManager/symbolTable 还原、EP 构造 M → 返回列表；建图会执行代码/换 checkerManager。
 * checker/antql/rules/antql-{getdefinition,hasflow}.ts：用户位置 K；图查询/合并 M → 替换 entryPoints。
 * checker/antql/rules/antql-{hasproperty,hasfunctioncall}.ts：用户关键词 K；图查询/去重 M → 替换 entryPoints。
 * checker/antql/util/entrypoint-util.ts：位置去重/合并；T/common-kit/{entry-points-util,taint-entrypoint-util}.ts：
 *   EP 补齐、union 展开、去重、注册。T/test-taint-checker.ts：图/文件兜底 → entryPoints。
 * checker/meta/generic-framework-checker.ts：旧 Spec target K；路径读取/complete M → entryPoints。
 * A/common/analyzer.ts、A/common/entrypoint/*、各语言 *analyzer.ts、spring-entrypoint-scheduler.ts：
 *   消费/调度/合并已发现入口，不额外发明框架识别；Go/PHP 合并 main，Go 消费动态 ruleEntrypoints。
 * src/incremental、metrics、报告、QL converter 和测试中的同名字段是过滤/输出/测试，不是独立发现器。
 * 全仓搜索未发现 C/C++ 独立 EntryPoint discovery，故不设计假想 C++ adapter。
 *
 * 原始操作 → 聚类（先归纳、后实现）：
 * 递归 AST/遍历包模块/文件 UUID → discovery；callee/receiver/位置参数/关键字/返回/赋值 → observation；
 * union 展开 ≠ 列表展开 ≠ 对象字段解包（三者不混同）；符号引用/定义定位 → resolution；
 * class members/类体/装饰器/modifiers/继承/接口 → structure；名称/签名/位置 → filtering；
 * WeakMap/注册函数映射/延迟候选 → relations；EP 补齐/receiver metadata/去重 → registration。
 *
 * 最终 Catalog：20 个算子。capture 是宿主边界，reset 是生命周期管理，二者不计入。
 * 名称 | 输入 → 输出 | 副作用 | 底层依赖 | 需要它的实现
 * scanDefinitions | AST/项目 → 定义句柄 | 无 | AstUtil.satisfy | Python collectors/Egg/Gradio
 * scanSymbols | analyzer → 符号句柄 | 无 | members/getMemberValue/symbolTable | main/Spring/PHP/配置入口
 * readCall | context 或表达式 → callee/receiver/参数/返回句柄 | 无 | getCallArgsFromInfo | 所有注册式/Gradio
 * readAssignment | context 或表达式 → 左右句柄 | 无 | Assignment/VariableDeclaration + rvalue | Cobra/urfave/FastAPI
 * expandAlternatives | 值句柄 → union 候选 | 无 | union.value | Beego/Tornado/restful
 * readElements | 集合句柄 → 单层元素 | 无 | 数组/tuple/数字键 ObjectExpression | Django/Tornado/Gradio
 * readMember | 对象+字段 → 值句柄 | 无 | getMemberValue/members/类值表 | PHP/Beego/Egg/gRPC
 * readMetadata | 句柄 → 名称/位置/参数/修饰符/装饰器 | 无 | AstBinding/UAST | Spring/Flask/Gin/PHP
 * readImports | AST → 导入别名关系 | 无 | UAST ImportExpression | FastAPI/Gradio/agentUniverse
 * resolveReference | 引用+scope → 值候选 | 无 | getMemberValue/parent | Gin wrapper/配置入口/回调
 * resolveFunction | 候选 → 已存在函数闭包句柄 | 无 | 符号扫描/定义 identity | 全部函数入口
 * resolveClass | 候选 → 已存在类/类定义句柄 | 无 | AstBinding.cdef/类值 | handler/PHP/gRPC
 * getMethods | 类 → 直接方法候选 | 无 | members/ClassDefinition.body | Beego/PHP/httpserver/Inference
 * getBaseTypes | 类 → 直接或 CHA 传递基类名 | 无 | supers/extends/typeResolver | Flask/PHP/Java
 * getSubTypes | 类 → CHA 子类型名 | 无 | typeResolver.findSubTypes | Java interface；缺 CHA 明确 unsupported
 * filterCandidates | 候选+宿主 predicate → 子集 | 无 | readMetadata | 所有实现；不是 JSON 条件语言
 * relationStore | 命名空间+身份+候选 → 保存数量 | 本库 Map | 对象身份 | Tornado/gRPC/Beego/FastAPI
 * relationLookup | 命名空间+身份 → 候选 | 无 | 本库 Map | 同上；不以全局裸变量名关联
 * queryGraphEntries | 已有图+roots/loc/keyword → 候选 | 不建图 | full-callgraph-file-entrypoint | default/callchain/AntQL
 * registerEntryPoint | 可执行候选+metadata → registered/duplicate/失败 | 仅追加入口 | complete/EntryPoint | 所有注册端
 *
 * 通用性检查：算子无框架/API 名称分支；名称表、参数位置、路径规则留给调用者。
 * 单次出现的特殊行为没有强行合并：配置格式解析、字符串路由协议、实例创建、执行工厂/初始化、
 * Java 重载克隆/override 分派、Python 装饰器执行仍是边界能力，不能声称 20 算子完整替代所有 checker。
 * readImports 只适配已观察的 ImportExpression；不把 JS require 自动等同 Python import。
 * getMethods 不创建实例、不声称完成 MRO；getSubTypes 只读现有 CHA，不按同名类猜实现关系。
 * resolveFunction 不合成 fclos、不执行 AST、不按名称选第一个；缺符号可在后续事件重试。
 * registration 保留真实 parent/_this，不伪造绑定；receiverType 是调度 metadata，不等于创建 receiver。
 *
 * 验证映射：Go Mux 注册 = readCall→resolveFunction→register；Java Spring = scanSymbols→
 * readMetadata→filter→register；Python handler/PHP 类约定 = scanDefinitions/scanSymbols→
 * getBaseTypes→getMethods→filter→resolveFunction→register；Gradio = readCall→resolveReference→register。
 * 内嵌测试验证这些原语的跨表示契约，不宣称已迁移 checker 或得到端到端检测等价性。
 * 下一阶段才设计 LLM 如何组合；不要开放任意 processInstruction、建图、文件执行给 LLM。
 */

const entryCandidateBrand: unique symbol = Symbol('EntryCandidate')

/** 只可交还给创建它的算子实例；不携带 YASA 内部对象。 */
export interface EntryCandidate {
  readonly [entryCandidateBrand]: true
}

export interface EntryOperatorResult<T> {
  status: 'ok' | 'not-found' | 'unsupported' | 'ambiguous'
  values: T[]
  reason?: string
}

export interface EntryCandidateMetadata {
  kind: 'function' | 'class' | 'file' | 'value'
  name?: string
  /** 源码中的限定表达式，仅作语法证据，不冒充已经解析的包身份。 */
  expression?: string
  literal?: string | number | boolean | null
  file?: string
  startLine?: number
  startColumn?: number
  endLine?: number
  endColumn?: number
  ownerName?: string
  /** 保留声明侧参数（包括语言声明中的 self），不擅自修改索引。 */
  parameters: { name?: string; type?: string }[]
  modifiers: string[]
  decorators: EntryCandidate[]
}

export interface EntryCallView {
  callee: EntryCandidate
  receiver?: EntryCandidate
  arguments: { kind: string; name?: string; index: number; candidate: EntryCandidate; evaluated: boolean }[]
  returned?: EntryCandidate
}

export interface EntryRegistrationOptions {
  kind?: 'function' | 'file'
  attribute?: string
  framework?: string
  receiverType?: string
  skipDecorators?: boolean
  isPreProcess?: boolean
  destination?: 'entryPoints' | 'mainEntryPoints' | 'ruleEntrypoints'
}

/**
 * 每个 analyzer/扫描创建一个实例；持有不透明句柄、关系和统一注册入口。
 * any 仅限本类与旧 analyzer 的适配边界；对外返回稳定 DTO/句柄。
 * 查询失败明确返回原因，既不执行目标源码，也不悄悄生成空闭包。
 */
export class GenericEntryPointOperators {
  private handles = new WeakMap<EntryCandidate, { value: any; owner?: any }>()

  private relations = new Map<string, Map<unknown, EntryCandidate[]>>()

  private identities = new WeakMap<object, number>()

  private nextIdentity = 1

  constructor(private readonly analyzer: any) {}

  /** 宿主把事件/AST/分析值送入库；规则不需要接触其内部字段。 */
  capture(value: unknown): EntryCandidate {
    return this.wrap(value)
  }

  /** 判断一个值是否为当前算子实例创建、且尚未 reset 的不透明句柄。 */
  isCandidate(value: unknown): value is EntryCandidate {
    return Boolean(value && typeof value === 'object' && this.handles.has(value as EntryCandidate))
  }

  /** 分析结束释放关系；旧句柄失效。不删除 analyzer 中已注册的入口。 */
  reset(): void {
    this.handles = new WeakMap()
    this.relations.clear()
    this.identities = new WeakMap()
    this.nextIdentity = 1
  }

  scanDefinitions(root?: EntryCandidate, kind?: 'function' | 'class' | 'file'): EntryOperatorResult<EntryCandidate> {
    const roots = root ? [this.raw(root)] : this.fileRoots()
    const expected = kind && { function: 'FunctionDefinition', class: 'ClassDefinition', file: 'CompileUnit' }[kind]
    const nodes =
      AstUtil.satisfy(
        roots,
        (n: any) =>
          Boolean(
            n &&
            (expected ? n.type === expected : ['FunctionDefinition', 'ClassDefinition', 'CompileUnit'].includes(n.type))
          ),
        (_n: any, key: string) => key !== '_field',
        undefined,
        true
      ) || []
    return this.result(
      nodes.map((n: any) => this.wrap(n)),
      '没有匹配的源码定义'
    )
  }

  scanSymbols(kind?: 'function' | 'class' | 'file'): EntryOperatorResult<EntryCandidate> {
    const ctx = this.analyzer?.topScope?.context
    const roots = [
      ctx?.packages,
      ctx?.modules,
      ...this.values(ctx?.funcs).map((v) => this.deref(v)),
      ...this.values(this.analyzer?.moduleScopes),
      ...this.values(this.analyzer?.classMap).map((v) => this.deref(v)),
      ...this.fileSymbols(),
    ]
    const queue = roots.filter(Boolean)
    const seen = new Set<unknown>()
    const found: EntryCandidate[] = []
    for (let i = 0; i < queue.length; i++) {
      const value = queue[i]
      if (!value || typeof value !== 'object' || seen.has(value)) continue
      seen.add(value)
      const candidate = this.wrap(value)
      const actualKind = this.readMetadata(candidate).kind
      if (actualKind !== 'value' && (!kind || actualKind === kind)) found.push(candidate)
      if (value.vtype !== 'fclos') queue.push(...this.memberEntries(value).map(([, child]) => child))
      if (value.vtype === 'union' && Array.isArray(value.value)) queue.push(...value.value)
    }
    return this.result(found, '分析器中尚无匹配的符号')
  }

  readCall(input: FrameworkTriggerContext | EntryCandidate): EntryOperatorResult<EntryCallView> {
    const isHandle = this.handles.has(input as EntryCandidate)
    const context = isHandle ? undefined : (input as FrameworkTriggerContext)
    const node: any = isHandle ? this.node(this.raw(input as EntryCandidate)) : context?.node
    if (!node || !['CallExpression', 'NewExpression'].includes(node.type)) {
      return this.failure('unsupported', '需要调用表达式或函数调用事件')
    }
    const info: any = context?.info
    const { getCallArgsFromInfo } = require('../../engine/analyzer/common/call-args')
    const callArgs = getCallArgsFromInfo(info?.callInfo)
    const args = callArgs
      ? callArgs.args.map((arg: any) => ({
          kind: arg.kind,
          name: arg.name,
          index: arg.index,
          candidate: this.wrap(arg.value),
          evaluated: true,
        }))
      : (node.arguments || []).map((arg: any, index: number) => ({
          kind:
            arg.type === 'VariableDeclaration'
              ? 'keyword'
              : ['SpreadElement', 'SpreadExpression'].includes(arg.type)
                ? 'spread'
                : 'positional',
          name: arg.type === 'VariableDeclaration' ? arg.id?.name : undefined,
          index,
          candidate: this.wrap(arg.type === 'VariableDeclaration' ? arg.init : arg),
          evaluated: false,
        }))
    const receiver = callArgs?.receiver ?? node.callee?.object
    return {
      status: 'ok',
      values: [
        {
          callee: this.wrap(info?.fclos ?? node.callee),
          receiver: receiver == null ? undefined : this.wrap(receiver),
          arguments: args,
          returned: info && Object.prototype.hasOwnProperty.call(info, 'ret') ? this.wrap(info.ret) : undefined,
        },
      ],
    }
  }

  readAssignment(input: FrameworkTriggerContext | EntryCandidate): EntryOperatorResult<{
    target: EntryCandidate
    assigned: EntryCandidate
    evaluated: boolean
  }> {
    const isHandle = this.handles.has(input as EntryCandidate)
    const context = isHandle ? undefined : (input as FrameworkTriggerContext)
    const node: any = isHandle ? this.node(this.raw(input as EntryCandidate)) : context?.node
    if (!node || !['AssignmentExpression', 'VariableDeclaration'].includes(node.type)) {
      return this.failure('unsupported', '需要赋值或变量声明事件')
    }
    const info: any = context?.info
    const evaluated = Boolean(info && Object.prototype.hasOwnProperty.call(info, 'rvalue'))
    return {
      status: 'ok',
      values: [
        {
          target: this.wrap(node.left ?? node.id),
          assigned: this.wrap(evaluated ? info.rvalue : (node.right ?? node.init)),
          evaluated,
        },
      ],
    }
  }

  /** 只展开候选并集，不把一个列表误拆成多个可能值。 */
  expandAlternatives(input: EntryCandidate): EntryOperatorResult<EntryCandidate> {
    const queue = [this.raw(input)]
    const seen = new Set<unknown>()
    const result: EntryCandidate[] = []
    for (let i = 0; i < queue.length; i++) {
      const value = queue[i]
      if (value == null || seen.has(value)) continue
      seen.add(value)
      if (value.vtype === 'union' && Array.isArray(value.value)) queue.push(...value.value)
      else result.push(this.wrap(value, this.handles.get(input)?.owner))
    }
    return this.result(result, '候选并集为空')
  }

  /** 只展开一层；保留 tuple 的位置，不递归丢失表结构。 */
  readElements(input: EntryCandidate): EntryOperatorResult<EntryCandidate> {
    const value = this.raw(input)
    if (Array.isArray(value))
      return this.result(
        value.map((v) => this.wrap(v)),
        '集合为空'
      )
    const node = this.node(value)
    if (['ArrayExpression', 'TupleExpression'].includes(node?.type)) {
      return this.result(
        (node.elements || []).map((v: any) => this.wrap(v)),
        '集合为空'
      )
    }
    if (node?.type === 'ObjectExpression') {
      const props = node.properties || []
      if (!props.every((p: any) => /^\d+$/.test(String(p.key?.value ?? p.key?.name ?? p.id?.name)))) {
        return this.failure('unsupported', '对象不是数字索引集合，请使用 readMember')
      }
      return this.result(
        [...props]
          .sort(
            (a: any, b: any) =>
              Number(a.key?.value ?? a.key?.name ?? a.id?.name) - Number(b.key?.value ?? b.key?.name ?? b.id?.name)
          )
          .map((p: any) => this.wrap(p.value ?? p.init)),
        '集合为空'
      )
    }
    const entries = this.memberEntries(value)
    if (entries.length && entries.every(([key]) => /^\d+$/.test(key))) {
      return this.result(
        entries.sort(([a], [b]) => Number(a) - Number(b)).map(([, v]) => this.wrap(v)),
        '集合为空'
      )
    }
    return this.failure('unsupported', '不是已支持的列表/tuple 表示')
  }

  readMember(input: EntryCandidate, name: string): EntryOperatorResult<EntryCandidate> {
    const value = this.raw(input)
    if (['__proto__', 'prototype', 'constructor'].includes(name))
      return this.failure('unsupported', '不读取宿主原型字段')
    if (value?.type === 'ObjectExpression') {
      const props = (value.properties || []).filter(
        (p: any) => String(p.key?.value ?? p.key?.name ?? p.id?.name) === name
      )
      return this.result(
        props.map((p: any) => this.wrap(p.value ?? p.init)),
        '对象字段不存在'
      )
    }
    const entries = this.memberEntries(value).filter(([key]) => key === name)
    return this.result(
      entries.map(([, child]) => this.wrap(child, value)),
      '对象成员不存在'
    )
  }

  readMetadata(input: EntryCandidate): EntryCandidateMetadata {
    const value = this.raw(input)
    const node = this.node(value)
    const loc = node?.loc
    const owner = this.handles.get(input)?.owner ?? value?.parent
    const modifiers = [
      ...(Array.isArray(node?.modifiers) ? node.modifiers : []),
      ...(Array.isArray(node?._meta?.modifiers) ? node._meta.modifiers : []),
    ]
    return {
      kind:
        node?.type === 'FunctionDefinition'
          ? 'function'
          : node?.type === 'ClassDefinition'
            ? 'class'
            : node?.type === 'CompileUnit'
              ? 'file'
              : 'value',
      name: node?.id?.name ?? node?.name ?? node?.property?.name ?? value?.sid,
      expression: node && ['Identifier', 'MemberAccess'].includes(node.type) ? AstUtil.prettyPrintAST(node) : undefined,
      literal:
        node?.type === 'Literal'
          ? node.value
          : value === null || ['string', 'number', 'boolean'].includes(typeof value)
            ? value
            : undefined,
      file: loc?.sourcefile,
      startLine: loc?.start?.line,
      startColumn: loc?.start?.column,
      endLine: loc?.end?.line,
      endColumn: loc?.end?.column,
      ownerName: this.node(owner)?.type === 'ClassDefinition' ? (this.node(owner)?.id?.name ?? owner?.sid) : undefined,
      parameters: (node?.parameters || node?.params || []).map((p: any) => ({
        name: p.id?.name ?? p.name,
        type: p.varType ? AstUtil.prettyPrintAST(p.varType) : undefined,
      })),
      modifiers: modifiers
        .map((m: any) => (typeof m === 'string' ? m : (m?.name ?? m?.value ?? m?.kind)))
        .filter(Boolean),
      decorators: (node?._meta?.decorators || []).map((d: any) => this.wrap(d)),
    }
  }

  /** ImportExpression 的文件内词法绑定，不做跨文件加载，也不猜 require/星号导入。 */
  readImports(root: EntryCandidate): EntryOperatorResult<{ local: string; imported: string; module?: string }> {
    const node = this.node(this.raw(root))
    if (node?.type !== 'CompileUnit')
      return this.failure('unsupported', '当前只读取模块顶层导入，避免混淆嵌套作用域别名')
    const nodes = (node.body || []).filter(
      (n: any) => n?.type === 'VariableDeclaration' && n.init?.type === 'ImportExpression'
    )
    return this.result(
      nodes.flatMap((n: any) => {
        const imported = n.init.imported?.name ?? n.init.imported?.value
        return n.id?.name && typeof imported === 'string'
          ? [
              {
                local: n.id.name,
                imported,
                module: n.init.from?.value,
              },
            ]
          : []
      }),
      '没有受支持的导入绑定'
    )
  }

  resolveReference(input: EntryCandidate, scope: EntryCandidate): EntryOperatorResult<EntryCandidate> {
    const value = this.raw(input)
    if (value?.vtype) return this.expandAlternatives(input)
    if (value?.type === 'MemberAccess') {
      const base = this.resolveReference(this.wrap(value.object), scope)
      const name = value.property?.name ?? value.property?.value
      if (typeof name !== 'string') return this.failure('unsupported', '动态成员名尚未求值')
      return this.result(
        base.values.flatMap((v) => this.readMember(v, name).values),
        '无法解析成员引用'
      )
    }
    if (value?.type !== 'Identifier')
      return this.failure('unsupported', '仅解析已有 Identifier/MemberAccess，不执行表达式')
    const seen = new Set<unknown>()
    for (let current = this.raw(scope); current && !seen.has(current); current = current.parent) {
      seen.add(current)
      const member = this.readMember(this.wrap(current), value.name)
      if (member.values.length) return member
    }
    return this.failure('not-found', '词法作用域中尚无该引用；可在后续事件重试')
  }

  resolveFunction(input: EntryCandidate): EntryOperatorResult<EntryCandidate> {
    const values: EntryCandidate[] = []
    for (const candidate of this.expandAlternatives(input).values) {
      const value = this.raw(candidate)
      if (value?.vtype === 'fclos' && this.node(value)?.type === 'FunctionDefinition') values.push(candidate)
      else if (this.node(value)?.type === 'FunctionDefinition') {
        const matches = this.scanSymbols('function').values.filter((v) =>
          this.sameDefinition(this.node(this.raw(v)), this.node(value))
        )
        values.push(...matches)
      }
    }
    return this.result(values, '没有对应的已解析函数闭包；不会按同名函数猜测或合成闭包')
  }

  resolveClass(input: EntryCandidate): EntryOperatorResult<EntryCandidate> {
    const values: EntryCandidate[] = []
    for (const candidate of this.expandAlternatives(input).values) {
      const value = this.raw(candidate)
      const cdef = value?.ast?.cdef ?? (this.node(value)?.type === 'ClassDefinition' ? this.node(value) : undefined)
      if (!cdef) continue
      if (value.vtype === 'class' || value.vtype === 'scope') values.push(candidate)
      else {
        const matches = this.scanSymbols('class').values.filter((v) =>
          this.sameDefinition(this.node(this.raw(v)), cdef)
        )
        values.push(...(matches.length ? matches : [this.wrap(cdef)]))
      }
    }
    return this.result(values, '没有类定义证据；不会将普通对象猜成类')
  }

  /** 直接方法，不遍历方法体里的嵌套函数；继承/MRO/实例创建不在此算子内。 */
  getMethods(input: EntryCandidate): EntryOperatorResult<EntryCandidate> {
    const value = this.raw(input)
    const node = this.node(value)
    if (node?.type !== 'ClassDefinition') return this.failure('unsupported', '需要先解析类')
    const body = Array.isArray(node.body) ? node.body : node.body?.body || []
    const runtime = this.memberEntries(value).filter(
      ([, v]) => !v?.inherited && this.node(v)?.type === 'FunctionDefinition'
    )
    const methods = runtime.map(([, v]) => this.wrap(v, value))
    for (const member of body) {
      if (member.type !== 'FunctionDefinition') continue
      if (!runtime.some(([, v]) => this.sameDefinition(this.node(v), member))) methods.push(this.wrap(member, value))
    }
    return this.result(methods, '类中没有直接方法')
  }

  getBaseTypes(input: EntryCandidate, transitive = false): EntryOperatorResult<string> {
    if (transitive) return this.relatedTypes(input, 'findBaseTypes')
    const value = this.raw(input)
    const node = value?.ast?.cdef ?? this.node(value)
    if (node?.type !== 'ClassDefinition') return this.failure('unsupported', '需要类定义')
    const bases = [...(node.supers || []), ...(node.extends ? [node.extends] : [])]
    return this.result(
      [
        ...new Set<string>(
          bases.map((v: any) => (typeof v === 'string' ? v : AstUtil.prettyPrintAST(v))).filter(Boolean)
        ),
      ],
      '没有直接基类'
    )
  }

  getSubTypes(input: EntryCandidate): EntryOperatorResult<string> {
    return this.relatedTypes(input, 'findSubTypes')
  }

  filterCandidates(
    inputs: EntryCandidate[],
    predicate: (metadata: EntryCandidateMetadata, candidate: EntryCandidate) => boolean
  ): EntryOperatorResult<EntryCandidate> {
    return this.result(
      inputs.filter((v) => predicate(this.readMetadata(v), v)),
      '没有满足条件的候选'
    )
  }

  relationStore(namespace: string, key: EntryCandidate, values: EntryCandidate[]): number {
    const rawKey = this.raw(key)
    values.forEach((v) => this.raw(v))
    let table = this.relations.get(namespace)
    if (!table) {
      table = new Map()
      this.relations.set(namespace, table)
    }
    const combined = [...(table.get(rawKey) || []), ...values]
    const seen = new Set<unknown>()
    const unique = combined.filter((v) => {
      const raw = this.raw(v)
      if (seen.has(raw)) return false
      seen.add(raw)
      return true
    })
    table.set(rawKey, unique)
    return unique.length
  }

  relationLookup(namespace: string, key: EntryCandidate): EntryOperatorResult<EntryCandidate> {
    return this.result([...(this.relations.get(namespace)?.get(this.raw(key)) || [])], '尚未记录该身份的关系')
  }

  queryGraphEntries(
    query: { kind: 'roots' } | { kind: 'locations'; locations: unknown[] } | { kind: 'keywords'; keywords: string[] }
  ): EntryOperatorResult<EntryCandidate> {
    const graph = this.analyzer?.ainfo?.callgraph
    if (!graph?.nodes || !graph?.edges) return this.failure('unsupported', '需要宿主事先构建调用图；算子不会启动建图')
    const helpers = require('../common/full-callgraph-file-entrypoint')
    const entries =
      query.kind === 'roots'
        ? helpers.getAllEntryPointsUsingCallGraph(graph, this.analyzer)
        : query.kind === 'locations'
          ? helpers.getEntryPointsUsingCallGraphByLoc(query.locations, graph, this.analyzer.fileManager, this.analyzer)
          : helpers.getEntryPointsUsingCallGraphByKeyWords(
              query.keywords,
              graph,
              this.analyzer.fileManager,
              this.analyzer
            )
    // 不泄漏 EP 对象；注册时由统一入口重新构造。
    return this.result(
      entries.filter((ep: any) => ep.entryPointSymVal).map((ep: any) => this.wrap(ep.entryPointSymVal)),
      '图查询没有入口候选'
    )
  }

  registerEntryPoint(
    input: EntryCandidate,
    options: EntryRegistrationOptions = {}
  ): EntryOperatorResult<{
    outcome: 'registered' | 'duplicate'
    metadata: EntryCandidateMetadata
  }> {
    let value = this.raw(input)
    const kind = options.kind ?? 'function'
    if (kind === 'function') {
      const resolution = this.resolveFunction(input)
      if (resolution.status !== 'ok') return this.failure(resolution.status, resolution.reason!)
      if (resolution.values.length !== 1) return this.failure('ambiguous', '多个函数候选必须显式逐个注册，不能任选一个')
      value = this.raw(resolution.values[0])
      if (!value.parent) return this.failure('unsupported', '函数缺少执行作用域，不能构造可执行入口')
    } else if (!value?.vtype || this.node(value)?.type !== 'CompileUnit') {
      return this.failure('unsupported', '文件入口需要已解析的模块符号，不接受裸 AST')
    }
    const metadata = this.readMetadata(this.wrap(value, this.handles.get(input)?.owner))
    const EntryPoint = require('../../engine/analyzer/common/entrypoint/entrypoint')
    const Constant = require('../../util/constant')
    const ep =
      kind === 'function'
        ? completeEntryPoint(value, options.isPreProcess ?? false)
        : new EntryPoint(Constant.ENGIN_START_FILE_BEGIN)
    ep.entryPointSymVal = value
    ep.scopeVal = kind === 'function' ? value.parent : value
    ep.argValues = kind === 'function' ? [] : undefined
    ep.filePath = metadata.file
    ep.functionName = kind === 'function' ? metadata.name : undefined
    ep.attribute = options.attribute ?? 'generic'
    ep.framework = options.framework
    ep.funcReceiverType = options.receiverType ?? value.funcReceiverType ?? metadata.ownerName
    ep.funcLocStart = metadata.startLine
    ep.funcLocEnd = metadata.endLine
    ep.skipDecorators = options.skipDecorators ?? false
    ep.isPreProcess = options.isPreProcess ?? false
    const destination = options.destination ?? 'entryPoints'
    if (this.analyzer[destination] != null && !Array.isArray(this.analyzer[destination])) {
      return this.failure('unsupported', '分析器入口容器不是数组')
    }
    const entries: any[] = this.analyzer[destination] ?? []
    const key = this.registrationKey(ep)
    if (entries.some((existing) => this.registrationKey(existing) === key)) {
      return { status: 'ok', values: [{ outcome: 'duplicate', metadata }] }
    }
    entries.push(ep)
    this.analyzer[destination] = entries
    return { status: 'ok', values: [{ outcome: 'registered', metadata }] }
  }

  // 以下是 YASA representation adapters，不属于供规则选择的算子。
  private wrap(value: any, owner?: any): EntryCandidate {
    const handle: EntryCandidate = Object.freeze({ [entryCandidateBrand]: true as const })
    this.handles.set(handle, { value, owner })
    return handle
  }

  private raw(handle: EntryCandidate): any {
    const found = this.handles.get(handle)
    if (!found) throw new Error('EntryCandidate 不属于当前分析，或已被 reset 释放')
    return found.value
  }

  private node(value: any): any {
    return value?.ast?.node ?? value?.ast?.fdef ?? value?.ast?.cdef ?? (value?.type ? value : undefined)
  }

  private values(value: any): any[] {
    return value && typeof value.values === 'function' ? [...value.values()] : Object.values(value || {})
  }

  private deref(value: any): any {
    return typeof value === 'string' ? (this.analyzer?.symbolTable?.get(value) ?? value) : value
  }

  private memberEntries(value: any): [string, any][] {
    const seen = new Set<unknown>()
    while (value && typeof value === 'object' && !seen.has(value)) {
      seen.add(value)
      if (typeof value.members?.entries === 'function') return [...value.members.entries()]
      const table = value.vtype ? (value.value ?? value._field) : value
      if (table?.vtype) {
        value = table
        continue
      }
      if (!table || typeof table !== 'object') return []
      return Object.keys(table).map((key) => [
        key,
        typeof value.getMemberValue === 'function' ? value.getMemberValue(key) : this.deref(table[key]),
      ])
    }
    return []
  }

  private fileSymbols(): any[] {
    const files = this.analyzer?.fileManager ?? this.analyzer?.topScope?.context?.files
    return this.values(files)
      .map((file) => this.deref(typeof file === 'string' ? file : file?.uuid) ?? file)
      .filter((file) => file && typeof file === 'object')
  }

  private fileRoots(): any[] {
    const files = this.analyzer?.fileManager ?? this.analyzer?.topScope?.context?.files
    return [
      ...this.values(files)
        .map((file) => file?.astNode)
        .filter(Boolean),
      ...this.fileSymbols()
        .map((file) => this.node(file))
        .filter(Boolean),
    ]
  }

  private result<T>(values: T[], reason: string): EntryOperatorResult<T> {
    return values.length ? { status: 'ok', values } : { status: 'not-found', values: [], reason }
  }

  private failure<T>(status: EntryOperatorResult<T>['status'], reason: string): EntryOperatorResult<T> {
    return { status, values: [], reason }
  }

  private sameDefinition(a: any, b: any): boolean {
    if (!a || !b) return false
    if (a === b) return true
    if (a._meta?.nodehash && b._meta?.nodehash) return a._meta.nodehash === b._meta.nodehash
    const x = a.loc
    const y = b.loc
    return Boolean(
      x?.sourcefile &&
      y?.sourcefile &&
      x.start?.line != null &&
      x.start?.column != null &&
      x.end?.line != null &&
      x.end?.column != null &&
      x.sourcefile === y.sourcefile &&
      x.start.line === y.start?.line &&
      x.start.column === y.start?.column &&
      x.end.line === y.end?.line &&
      x.end.column === y.end?.column &&
      a.type === b.type
    )
  }

  private relatedTypes(input: EntryCandidate, method: 'findBaseTypes' | 'findSubTypes'): EntryOperatorResult<string> {
    const value = this.raw(input)
    const resolver = this.analyzer?.typeResolver
    const map = this.analyzer?.classHierarchyMap ?? resolver?.classHierarchyMap
    const hierarchy = map?.get(value?.qid)
    if (!hierarchy || typeof resolver?.[method] !== 'function') {
      return this.failure('unsupported', '缺少该类型的 CHA 身份/查询能力，不使用短类名猜测')
    }
    return this.result([...new Set<string>(resolver[method](hierarchy))], '类型关系为空')
  }

  private identity(value: any): string {
    if (!value || typeof value !== 'object') return String(value)
    let id = this.identities.get(value)
    if (id === undefined) {
      id = this.nextIdentity++
      this.identities.set(value, id)
    }
    return String(id)
  }

  private registrationKey(ep: any): string {
    const value = ep.entryPointSymVal
    const node = this.node(value)
    const loc = node?.loc
    const definition =
      node?._meta?.nodehash ??
      (loc?.sourcefile &&
      loc.start?.line != null &&
      loc.start?.column != null &&
      loc.end?.line != null &&
      loc.end?.column != null
        ? JSON.stringify(loc)
        : this.identity(value))
    // 不能仅按方法名或行号去重：保留实例、闭包环境、receiver 类型和执行策略差异。
    return JSON.stringify([
      ep.type,
      definition,
      this.identity(value?.parent),
      this.identity(value?._this),
      ep.funcReceiverType ?? '',
      ep.skipDecorators ?? false,
      ep.isPreProcess ?? false,
    ])
  }
}

export interface FrameworkTriggerContext {
  analyzer?: unknown
  scope?: unknown
  node?: unknown
  state?: unknown
  info?: unknown
  memory?: Record<string, unknown>
}

/**
 * 判断一个未知值是否可以按字段读取。
 * @param value 待判断的值
 * @returns {boolean} 是否可以按字段读取
 */
function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object'
}

/**
 * 从 trigger context 读取路径；数字路径段可以访问数组，例如 info.args.0。
 * @param context 当前触发上下文
 * @param targetPath 点号分隔的字段路径
 * @returns {unknown} 找到的值；路径不存在时返回 undefined
 */
function readContextPath(context: FrameworkTriggerContext, targetPath: string): unknown {
  let current: unknown = context
  for (const part of targetPath.split('.')) {
    if (Array.isArray(current) && /^\d+$/.test(part)) {
      current = current[Number(part)]
    } else if (isRecord(current)) {
      current = current[part]
    } else {
      return undefined
    }
  }
  return current
}

/**
 * 判断一条匹配条件是否成立。
 * @param context 当前触发上下文
 * @param condition 匹配条件
 * @returns {boolean} 是否匹配
 */
// eslint-disable-next-line complexity
function conditionMatches(context: FrameworkTriggerContext, condition: FrameworkMatchCondition): boolean {
  const actual = readContextPath(context, condition.path)

  return matchOperatorValue(actual, condition.operator, condition.value)
}

/** Framework rule 与 EntryPoint candidate 共用的纯值比较语义。 */
function matchOperatorValue(
  actual: unknown,
  operator: FrameworkMatchCondition['operator'],
  expected: unknown
): boolean {
  switch (operator) {
    case 'equals':
      return Object.is(actual, expected)
    case 'notEquals':
      return !Object.is(actual, expected)
    case 'includes':
      if (typeof actual === 'string' && typeof expected === 'string') {
        return actual.includes(expected)
      }
      return Array.isArray(actual) && actual.some((item) => Object.is(item, expected))
    case 'startsWith':
      return typeof actual === 'string' && typeof expected === 'string' && actual.startsWith(expected)
    case 'endsWith':
      return typeof actual === 'string' && typeof expected === 'string' && actual.endsWith(expected)
    case 'oneOf':
      return Array.isArray(expected) && expected.some((item) => Object.is(actual, item))
    case 'exists':
      return expected === false ? actual === undefined || actual === null : actual !== undefined && actual !== null
    default:
      return false
  }
}

/**
 * 判断一条规则的 all/any 条件是否成立。
 * @param context 当前触发上下文
 * @param match 规则匹配部分
 * @returns {boolean} 是否匹配
 */
function ruleMatches(context: FrameworkTriggerContext, match: FrameworkRuleMatch): boolean {
  const allConditions = match.all || []
  const anyConditions = match.any || []
  const allMatch = allConditions.every((condition) => conditionMatches(context, condition))
  const anyMatch = anyConditions.length === 0 || anyConditions.some((condition) => conditionMatches(context, condition))
  return allMatch && anyMatch
}

/**
 * analyze 阶段的通用 Checker，输入是 FrameworkModeler 根据 UAST 生成的 FrameworkSpec。
 *
 * 它不理解 Django、Gin 等具体框架，只按 trigger 查找规则并执行已经注册的基础动作。
 */
class GenericFrameworkChecker extends Checker {
  private readonly rulesByTrigger = new Map<FrameworkTrigger, FrameworkSemanticRule[]>()

  private readonly entryPointPlansByTrigger = new Map<FrameworkTrigger, FrameworkEntryPointPlan[]>()

  private readonly memory: Record<string, unknown> = {}

  private entryPointOperators?: GenericEntryPointOperators

  private readonly operatorDiagnostics = new Set<string>()

  private readonly framework: string

  private startHookInstalled = false

  /**
   * 创建通用框架 Checker。
   *
   * @param resultManager YASA 结果管理器
   * @param spec FrameworkModeler 生成的规则
   */
  constructor(resultManager: unknown, spec: FrameworkSpec) {
    super(resultManager, spec.checkerId)
    this.framework = spec.framework

    for (const rule of Array.isArray(spec.rules) ? spec.rules : []) {
      const rules = this.rulesByTrigger.get(rule.trigger) || []
      rules.push(rule)
      this.rulesByTrigger.set(rule.trigger, rules)
    }
    for (const plan of Array.isArray(spec.entryPointPlans) ? spec.entryPointPlans : []) {
      const plans = this.entryPointPlansByTrigger.get(plan.trigger) || []
      plans.push(plan)
      this.entryPointPlansByTrigger.set(plan.trigger, plans)
    }
  }

  /**
   * 返回当前框架实际需要订阅的触发点。
   *
   * @returns {string[]} 触发点名称列表
   */
  getSubscriptions(): string[] {
    const subscriptions = new Set([...this.rulesByTrigger.keys(), ...this.entryPointPlansByTrigger.keys()])
    // 当前 runtime 动态注册表没有 startOfAnalyze 映射；先订阅 compileUnit，届时只安装 start hook。
    if (subscriptions.has('startOfAnalyze')) subscriptions.add('compileUnit')
    return Array.from(subscriptions)
  }

  /**
   * 执行某个触发点下的全部框架规则。
   *
   * @param trigger 当前触发点名称
   * @param context YASA 提供的执行上下文
   */
  executeTrigger(trigger: FrameworkTrigger, context: FrameworkTriggerContext): void {
    context.memory = this.memory
    if (context.analyzer) {
      this.entryPointOperators ??= new GenericEntryPointOperators(context.analyzer)
      for (const plan of this.entryPointPlansByTrigger.get(trigger) || []) {
        this.executeEntryPointPlan(plan, context)
      }
    }
    for (const rule of this.rulesByTrigger.get(trigger) || []) {
      if (!ruleMatches(context, rule.match)) continue

      const target = readContextPath(context, rule.action.target)
      this.executeAction(context, target, rule.action, rule)
    }
  }

  /** 逐步执行 LLM 生成的线性算子计划；任一步没有候选时，本次事件自然停止。 */
  private executeEntryPointPlan(plan: FrameworkEntryPointPlan, context: FrameworkTriggerContext): void {
    const outputs = new Map<string, unknown[]>([['$event', [context]]])
    let previous = '$event'
    for (const step of plan.steps || []) {
      const sourceName = step.from || previous
      const input = outputs.get(sourceName)
      if (!input) {
        this.operatorDiagnostic(plan, step, `from 引用了尚不存在的步骤：${sourceName}`)
        return
      }
      const output = this.executeEntryPointStep(step, input, outputs, context, plan)
      outputs.set(step.id, output)
      previous = step.id
      if (output.length === 0) return
    }
  }

  /** 把可序列化步骤适配到类型化 Operator API；这里不包含任何框架名称。 */
  // eslint-disable-next-line complexity, sonarjs/cognitive-complexity
  private executeEntryPointStep(
    step: FrameworkEntryPointOperatorStep,
    input: unknown[],
    outputs: Map<string, unknown[]>,
    context: FrameworkTriggerContext,
    plan: FrameworkEntryPointPlan
  ): unknown[] {
    const operators = this.entryPointOperators!
    const options = step.options || {}
    const candidates = input.filter((value): value is EntryCandidate => operators.isCandidate(value))
    const collect = <T>(result: EntryOperatorResult<T>): T[] => {
      if (result.status === 'unsupported' || result.status === 'ambiguous') {
        this.operatorDiagnostic(plan, step, result.reason || result.status)
      }
      return result.values
    }

    switch (step.operator) {
      case 'scanDefinitions': {
        const root =
          candidates.length === 1
            ? candidates[0]
            : context.node && (context.node as { type?: string }).type === 'CompileUnit'
              ? operators.capture(context.node)
              : undefined
        return collect(operators.scanDefinitions(root, options.kind))
      }
      case 'scanSymbols':
        return collect(operators.scanSymbols(options.kind))
      case 'readCall':
        return input.flatMap((value) => {
          const result = collect(
            operators.readCall(operators.isCandidate(value) ? value : (value as FrameworkTriggerContext))
          )
          return result.flatMap((view) => this.selectCallView(view, options))
        })
      case 'readAssignment':
        return input.flatMap((value) =>
          collect(
            operators.readAssignment(operators.isCandidate(value) ? value : (value as FrameworkTriggerContext))
          ).flatMap((view) =>
            options.select === 'target' ? [view.target] : options.select === 'assigned' ? [view.assigned] : []
          )
        )
      case 'expandAlternatives':
        return candidates.flatMap((value) => collect(operators.expandAlternatives(value)))
      case 'readElements':
        return candidates.flatMap((value) => collect(operators.readElements(value)))
      case 'readMember':
        if (typeof options.member !== 'string') {
          this.operatorDiagnostic(plan, step, 'readMember 缺少 options.member')
          return []
        }
        return candidates.flatMap((value) => collect(operators.readMember(value, options.member!)))
      case 'readMetadata':
        return candidates.map((value) => operators.readMetadata(value))
      case 'readImports':
        return candidates.flatMap((value) => collect(operators.readImports(value)))
      case 'resolveReference': {
        if (!context.scope) {
          this.operatorDiagnostic(plan, step, '当前事件没有可用于 resolveReference 的 scope')
          return []
        }
        const scope = operators.capture(context.scope)
        return candidates.flatMap((value) => collect(operators.resolveReference(value, scope)))
      }
      case 'resolveFunction':
        return candidates.flatMap((value) => collect(operators.resolveFunction(value)))
      case 'resolveClass':
        return candidates.flatMap((value) => collect(operators.resolveClass(value)))
      case 'getMethods':
        return candidates.flatMap((value) => collect(operators.getMethods(value)))
      case 'getBaseTypes':
        return candidates.flatMap((value) => collect(operators.getBaseTypes(value, options.transitive === true)))
      case 'getSubTypes':
        return candidates.flatMap((value) => collect(operators.getSubTypes(value)))
      case 'filterCandidates':
        return collect(
          operators.filterCandidates(candidates, (metadata, candidate) =>
            this.candidateFilterMatches(candidate, metadata, options.conditions, operators)
          )
        )
      case 'relationStore': {
        if (!options.namespace || !options.keyFrom) {
          this.operatorDiagnostic(plan, step, 'relationStore 缺少 namespace 或 keyFrom')
          return []
        }
        const keys = (outputs.get(options.keyFrom) || []).filter((value): value is EntryCandidate =>
          operators.isCandidate(value)
        )
        for (const key of keys) operators.relationStore(options.namespace, key, candidates)
        return candidates
      }
      case 'relationLookup':
        if (!options.namespace) {
          this.operatorDiagnostic(plan, step, 'relationLookup 缺少 namespace')
          return []
        }
        return candidates.flatMap((key) => collect(operators.relationLookup(options.namespace!, key)))
      case 'queryGraphEntries': {
        if (options.queryKind === 'roots') return collect(operators.queryGraphEntries({ kind: 'roots' }))
        if (options.queryKind === 'locations') {
          return collect(operators.queryGraphEntries({ kind: 'locations', locations: options.locations || [] }))
        }
        if (options.queryKind === 'keywords') {
          return collect(operators.queryGraphEntries({ kind: 'keywords', keywords: options.keywords || [] }))
        }
        this.operatorDiagnostic(plan, step, 'queryGraphEntries 缺少 queryKind')
        return []
      }
      case 'registerEntryPoint':
        return candidates.flatMap((candidate) => {
          const result = collect(
            operators.registerEntryPoint(candidate, {
              kind: options.kind === 'file' ? 'file' : 'function',
              attribute: options.attribute,
              framework: options.framework || this.framework,
              receiverType: options.receiverType,
              skipDecorators: options.skipDecorators,
              isPreProcess: options.isPreProcess,
              destination: options.destination,
            })
          )
          for (const registered of result) {
            if (registered.outcome === 'registered') this.printOperatorEntryPoint(plan, step, registered.metadata)
          }
          return result
        })
      default:
        this.operatorDiagnostic(plan, step, `未知算子：${String(step.operator)}`)
        return []
    }
  }

  private selectCallView(
    view: EntryCallView,
    options: NonNullable<FrameworkEntryPointOperatorStep['options']>
  ): EntryCandidate[] {
    if (options.select === 'callee') return [view.callee]
    if (options.select === 'receiver') return view.receiver ? [view.receiver] : []
    if (options.select === 'return') return view.returned ? [view.returned] : []
    if (options.select !== 'argument' && options.select !== 'arguments') return []
    const matches = view.arguments.filter(
      (arg) =>
        (options.index === undefined || arg.index === options.index) &&
        (options.name === undefined || arg.name === options.name) &&
        (options.argumentKind === undefined || arg.kind === options.argumentKind)
    )
    return (options.select === 'argument' ? matches.slice(0, 1) : matches).map((arg) => arg.candidate)
  }

  private candidateFilterMatches(
    candidate: EntryCandidate,
    metadata: EntryCandidateMetadata,
    filter: FrameworkCandidateFilter | undefined,
    operators: GenericEntryPointOperators
  ): boolean {
    if (!filter) return true
    const all = filter.all || []
    const any = filter.any || []
    return (
      all.every((condition) => this.candidateConditionMatches(candidate, metadata, condition, operators)) &&
      (any.length === 0 ||
        any.some((condition) => this.candidateConditionMatches(candidate, metadata, condition, operators)))
    )
  }

  private candidateConditionMatches(
    candidate: EntryCandidate,
    metadata: EntryCandidateMetadata,
    condition: FrameworkCandidateCondition,
    operators: GenericEntryPointOperators
  ): boolean {
    let actual: unknown
    if (condition.field === 'parameterCount') actual = metadata.parameters.length
    else if (condition.field === 'modifier') actual = metadata.modifiers
    else if (condition.field === 'baseType') {
      actual = operators.getBaseTypes(candidate, condition.transitive === true).values
    } else if (condition.field === 'decoratorName' || condition.field === 'decoratorExpression') {
      actual = metadata.decorators.flatMap((decorator) => {
        const call = operators.readCall(decorator)
        if (call.status === 'ok') {
          return call.values
            .map((view) => operators.readMetadata(view.callee))
            .map((item) => (condition.field === 'decoratorName' ? item.name : item.expression))
            .filter(Boolean)
        }
        const item = operators.readMetadata(decorator)
        return [condition.field === 'decoratorName' ? item.name : item.expression].filter(Boolean)
      })
    } else actual = metadata[condition.field]

    if (Array.isArray(actual)) {
      if (condition.operator === 'exists') return condition.value === false ? actual.length === 0 : actual.length > 0
      if (condition.operator === 'notEquals') {
        return actual.every((value) => matchOperatorValue(value, condition.operator, condition.value))
      }
      return actual.some((value) => matchOperatorValue(value, condition.operator, condition.value))
    }
    return matchOperatorValue(actual, condition.operator, condition.value)
  }

  private operatorDiagnostic(
    plan: FrameworkEntryPointPlan,
    step: FrameworkEntryPointOperatorStep,
    reason: string
  ): void {
    const key = `${plan.id}:${step.id}:${reason}`
    if (this.operatorDiagnostics.has(key)) return
    this.operatorDiagnostics.add(key)
    logger.warn(
      `[meta][entrypoint-plan] ${JSON.stringify({
        checkerId: this.getCheckerId(),
        planId: plan.id,
        stepId: step.id,
        operator: step.operator,
        reason,
      })}`
    )
  }

  private printOperatorEntryPoint(
    plan: FrameworkEntryPointPlan,
    step: FrameworkEntryPointOperatorStep,
    metadata: EntryCandidateMetadata
  ): void {
    console.log(
      `[meta][entrypoint] ${JSON.stringify(
        {
          checkerId: this.getCheckerId(),
          planId: plan.id,
          stepId: step.id,
          trigger: plan.trigger,
          file: metadata.file || null,
          startLine: metadata.startLine ?? null,
          endLine: metadata.endLine ?? null,
          className: metadata.ownerName || null,
          functionName: metadata.name || null,
        },
        null,
        2
      )}`
    )
  }

  /**
   * 执行 FrameworkSpec 中的基础动作。
   * @param context 当前触发上下文
   * @param target action.target 指向的值
   * @param action 动作配置
   * @param rule 当前规则
   */
  private executeAction(
    context: FrameworkTriggerContext,
    target: unknown,
    action: FrameworkRuleAction,
    rule: FrameworkSemanticRule
  ): void {
    if (action.type === 'markSource') {
      const before = getMarkedSourceCount()
      markTaintSource(target, {
        path: context.node,
        kind: action.options?.sourceKind || 'PYTHON_INPUT',
      })
      if (getMarkedSourceCount() > before) this.printIdentification('source', context, target, rule)
    } else if (action.type === 'registerEntryPoint') {
      const analyzer = context.analyzer as { entryPoints: unknown[] }
      analyzer.entryPoints.push(completeEntryPoint(target))
      this.printIdentification('entrypoint', context, target, rule)
    } else if (action.type === 'rememberValue') {
      const key = String(action.options?.key || rule.id)
      this.memory[key] = target
    }
  }

  /** 只打印本 Checker 实际执行的识别动作，不推断其他 Checker 的结果。 */
  private printIdentification(
    type: 'entrypoint' | 'source',
    context: FrameworkTriggerContext,
    target: any,
    rule: FrameworkSemanticRule
  ): void {
    try {
      const node = type === 'entrypoint' ? target?.ast?.node : (context.node as any)
      const owner = type === 'entrypoint' ? target?.parent?.ast?.node : undefined
      console.log(
        `[meta][${type}] ${JSON.stringify(
          {
            checkerId: this.getCheckerId(),
            ruleId: rule.id,
            trigger: rule.trigger,
            target: rule.action.target,
            file: node?.loc?.sourcefile || null,
            startLine: node?.loc?.start?.line ?? null,
            endLine: node?.loc?.end?.line ?? null,
            ...(type === 'entrypoint'
              ? {
                  className: owner?.type === 'ClassDefinition' ? owner.id?.name : null,
                  functionName: target?.functionName || node?.id?.name || null,
                }
              : {
                  expression: AstUtil.prettyPrint(node),
                  valueName: typeof target?.sid === 'string' ? target.sid : null,
                  sourceKind: rule.action.options?.sourceKind || 'PYTHON_INPUT',
                }),
          },
          null,
          2
        )}`
      )
    } catch {
      // 输出诊断信息失败不改变分析结果。
    }
  }

  /** 在模块/符号准备完成后执行静态入口发现计划。 */
  triggerAtStartOfAnalyze(analyzer: unknown, scope: unknown, node: unknown, state: unknown, info: unknown): void {
    this.executeTrigger('startOfAnalyze', { analyzer, scope, node, state, info })
  }

  /**
   * 将 YASA 的 CompileUnit 触发点转发给规则执行器。
   * @param analyzer Analyzer 实例
   * @param scope 当前作用域
   * @param node 当前节点
   * @param state 当前分析状态
   * @param info 触发附加信息
   */
  triggerAtCompileUnit(analyzer: unknown, scope: unknown, node: unknown, state: unknown, info: unknown): void {
    this.installStartHook(analyzer)
    this.executeTrigger('compileUnit', { analyzer, scope, node, state, info })
  }

  /**
   * 动态 checker 是 preProcess 前注册的，但 CheckerManager 的 runtime triggerMap 尚无 startOfAnalyze。
   * 这里在第一次 compileUnit 时把自己接入已有 checkpoint；不替换 analyzer 方法，也不执行入口计划。
   */
  private installStartHook(analyzer: unknown): void {
    if (this.startHookInstalled || !this.entryPointPlansByTrigger.has('startOfAnalyze')) return
    const manager = (analyzer as { getCheckerManager?: () => any })?.getCheckerManager?.()
    const checkpoint = manager?.checkpoints?.check_at_start_analyze
    if (!Array.isArray(checkpoint)) {
      logger.warn(`[meta][entrypoint-plan] ${this.getCheckerId()} 无法订阅 startOfAnalyze`)
      return
    }
    if (!checkpoint.includes(this)) checkpoint.push(this)
    this.startHookInstalled = true
  }

  /**
   * 将 YASA 的 EndOfCompileUnit 触发点转发给规则执行器。
   * @param analyzer Analyzer 实例
   * @param scope 当前作用域
   * @param node 当前节点
   * @param state 当前分析状态
   * @param info 触发附加信息
   */
  triggerAtEndOfCompileUnit(analyzer: unknown, scope: unknown, node: unknown, state: unknown, info: unknown): void {
    this.executeTrigger('endOfCompileUnit', { analyzer, scope, node, state, info })
  }

  /**
   * 将 YASA 的 Assignment 触发点转发给规则执行器。
   * @param analyzer Analyzer 实例
   * @param scope 当前作用域
   * @param node 当前节点
   * @param state 当前分析状态
   * @param info 触发附加信息
   */
  triggerAtAssignment(analyzer: unknown, scope: unknown, node: unknown, state: unknown, info: unknown): void {
    this.executeTrigger('assignment', { analyzer, scope, node, state, info })
  }

  /**
   * 将 YASA 的 FunctionCallBefore 触发点转发给规则执行器。
   * @param analyzer Analyzer 实例
   * @param scope 当前作用域
   * @param node 当前节点
   * @param state 当前分析状态
   * @param info 触发附加信息
   */
  triggerAtFunctionCallBefore(analyzer: unknown, scope: unknown, node: unknown, state: unknown, info: unknown): void {
    this.executeTrigger('functionCallBefore', { analyzer, scope, node, state, info })
  }

  /**
   * 将 YASA 的 FunctionCallAfter 触发点转发给规则执行器。
   * @param analyzer Analyzer 实例
   * @param scope 当前作用域
   * @param node 当前节点
   * @param state 当前分析状态
   * @param info 触发附加信息
   */
  triggerAtFunctionCallAfter(analyzer: unknown, scope: unknown, node: unknown, state: unknown, info: unknown): void {
    this.executeTrigger('functionCallAfter', { analyzer, scope, node, state, info })
  }

  /**
   * 将 YASA 的 MemberAccess 触发点转发给规则执行器。
   * @param analyzer Analyzer 实例
   * @param scope 当前作用域
   * @param node 当前节点
   * @param state 当前分析状态
   * @param info 触发附加信息
   */
  triggerAtMemberAccess(analyzer: unknown, scope: unknown, node: unknown, state: unknown, info: unknown): void {
    this.executeTrigger('memberAccess', { analyzer, scope, node, state, info })
  }
}

module.exports = GenericFrameworkChecker
// 保持原有 require(...) 返回 Checker 类；新增库作为命名属性供宿主/测试使用。
module.exports.GenericEntryPointOperators = GenericEntryPointOperators

/**
 * 显式调用的内嵌契约测试：只为遵守“所有代码留在本文件”而放在这里。
 * 不在加载 checker 时执行；不调用 LLM，不扫描用户项目，不改全局注册表。
 * 运行（日志也限制在 tmpdata）：
 * node --require tsx/cjs -e 'const c=require("./src/config"); c.logDir="./tmpdata/entrypoint-operators";
 * console.log(require("./src/checker/meta/generic-framework-checker").testEntryPointOperators())'
 */
function testEntryPointOperators(): { passed: number; cases: string[] } {
  const assert = require('node:assert/strict')
  const cases: string[] = []
  const test = (name: string, run: () => void) => {
    run()
    cases.push(name)
  }
  const loc = (file: string, line: number, column = 0) => ({
    sourcefile: file,
    start: { line, column },
    end: { line: line + 2, column: 1 },
  })
  const definition = (name: string, file = '/virtual/a.py', line = 1, column = 0): any => ({
    type: 'FunctionDefinition',
    id: { type: 'Identifier', name },
    parameters: [],
    body: [],
    loc: loc(file, line, column),
  })
  const scope: any = { vtype: 'scope', value: {} }
  const fn = (node: any, parent: any = scope): any => ({ vtype: 'fclos', ast: { node }, parent, sid: node.id.name })
  const first = fn(definition('callback'))
  const second = fn(definition('callback', '/virtual/b.py'))
  scope.value.callback = first
  const analyzer: any = {
    entryPoints: [],
    topScope: { context: { modules: scope, funcs: { first, second } } },
    symbolTable: new Map(),
  }
  const ops = new GenericEntryPointOperators(analyzer)
  const one = <T>(result: EntryOperatorResult<T>): T => {
    assert.equal(result.status, 'ok', result.reason)
    assert.equal(result.values.length, 1)
    return result.values[0]
  }

  test('注册式调用：显式参数不包含 receiver，保留 keyword/spread', () => {
    const view = one(
      ops.readCall({
        node: { type: 'CallExpression', callee: { type: 'Identifier', name: 'bind' } },
        info: {
          callInfo: {
            callArgs: {
              receiver: scope,
              args: [
                { kind: 'positional', index: 0, value: first },
                { kind: 'keyword', name: 'option', index: 1, value: false },
                { kind: 'spread', index: 2, value: [] },
              ],
            },
          },
          ret: second,
        },
      })
    )
    assert.deepEqual(
      view.arguments.map((a) => a.kind),
      ['positional', 'keyword', 'spread']
    )
    assert.equal(view.arguments[0].evaluated, true)
    assert.equal(ops.readMetadata(view.returned!).file, '/virtual/b.py')
    const result = one(ops.registerEntryPoint(view.arguments[0].candidate))
    assert.equal(result.outcome, 'registered')
    assert.equal(analyzer.entryPoints[0].entryPointSymVal, first)
  })
  test('重复事件不重复注册；同名不同文件保留', () => {
    assert.equal(one(ops.registerEntryPoint(ops.capture(first))).outcome, 'duplicate')
    assert.equal(one(ops.registerEntryPoint(ops.capture(second))).outcome, 'registered')
    assert.equal(analyzer.entryPoints.length, 2)
  })
  test('receiver 实例、预处理和装饰器策略不混合去重', () => {
    const a = { ...first, _this: {} }
    const b = { ...first, _this: {} }
    for (const value of [a, b]) assert.equal(one(ops.registerEntryPoint(ops.capture(value))).outcome, 'registered')
    assert.equal(one(ops.registerEntryPoint(ops.capture(first), { isPreProcess: true })).outcome, 'registered')
    assert.equal(one(ops.registerEntryPoint(ops.capture(first), { skipDecorators: true })).outcome, 'registered')
  })
  test('没有位置时不同闭包不被合并', () => {
    const node = definition('anonymous')
    delete node.loc
    const a = fn(node)
    const b = fn(node)
    assert.equal(one(ops.registerEntryPoint(ops.capture(a))).outcome, 'registered')
    assert.equal(one(ops.registerEntryPoint(ops.capture(b))).outcome, 'registered')
  })
  test('AST 精确解析，不因另一个文件有同名函数而选错', () => {
    assert.equal(ops.readMetadata(one(ops.resolveFunction(ops.capture(first.ast.node)))).file, '/virtual/a.py')
    assert.equal(ops.resolveFunction(ops.capture(definition('callback', '/virtual/missing.py'))).status, 'not-found')
  })
  test('未解析引用、无作用域函数和裸 AST 文件都拒绝注册', () => {
    const before = analyzer.entryPoints.length
    assert.equal(ops.registerEntryPoint(ops.capture({ type: 'Identifier', name: 'callback' })).status, 'not-found')
    assert.equal(ops.registerEntryPoint(ops.capture(fn(definition('x'), null))).status, 'unsupported')
    assert.equal(ops.registerEntryPoint(ops.capture({ type: 'CompileUnit' }), { kind: 'file' }).status, 'unsupported')
    assert.equal(analyzer.entryPoints.length, before)
  })
  test('union 的多个候选必须显式选择；循环 union 收敛', () => {
    const union: any = { vtype: 'union', value: [first, second] }
    union.value.push(union)
    assert.equal(ops.expandAlternatives(ops.capture(union)).values.length, 2)
    assert.equal(ops.registerEntryPoint(ops.capture(union)).status, 'ambiguous')
    assert.equal(ops.expandAlternatives(ops.capture([first, second])).values.length, 1)
  })
  test('单层集合保持 tuple 边界和数字索引顺序', () => {
    const nested = [first, second]
    const entries = ops.readElements(ops.capture([nested])).values
    assert.equal(entries.length, 1)
    assert.equal(ops.readElements(entries[0]).values.length, 2)
    const table = {
      type: 'ObjectExpression',
      properties: [
        { key: { value: 1 }, value: second },
        { key: { value: 0 }, value: first },
      ],
    }
    assert.equal(ops.readMetadata(ops.readElements(ops.capture(table)).values[0]).file, '/virtual/a.py')
    assert.equal(ops.readElements(ops.capture({ name: first })).status, 'unsupported')
  })
  test('赋值事件使用求值后的 rvalue，不误用旧 lvalue', () => {
    const view = one(
      ops.readAssignment({
        node: { type: 'AssignmentExpression', left: { type: 'Identifier', name: 'action' }, right: {} },
        info: { lvalue: second, rvalue: first },
      })
    )
    assert.equal(view.evaluated, true)
    assert.equal(ops.readMetadata(view.assigned).file, '/virtual/a.py')
  })
  test('词法遮蔽、成员引用、循环 parent 和导出对象导航', () => {
    const inner: any = { vtype: 'scope', value: { callback: second, exported: { value: first } }, parent: scope }
    assert.equal(
      ops.readMetadata(
        one(ops.resolveReference(ops.capture({ type: 'Identifier', name: 'callback' }), ops.capture(inner)))
      ).file,
      '/virtual/b.py'
    )
    const ref = { type: 'MemberAccess', object: { type: 'Identifier', name: 'exported' }, property: { name: 'value' } }
    assert.equal(
      ops.readMetadata(one(ops.resolveReference(ops.capture(ref), ops.capture(inner)))).file,
      '/virtual/a.py'
    )
    inner.parent = inner
    assert.equal(
      ops.resolveReference(ops.capture({ type: 'Identifier', name: 'absent' }), ops.capture(inner)).status,
      'not-found'
    )
  })
  test('关系按对象身份和命名空间隔离，重复句柄不重复关系', () => {
    const a = {}
    const b = {}
    assert.equal(ops.relationStore('bindings', ops.capture(a), [ops.capture(first), ops.capture(first)]), 1)
    assert.equal(ops.relationLookup('bindings', ops.capture(a)).values.length, 1)
    assert.equal(ops.relationLookup('bindings', ops.capture(b)).status, 'not-found')
    assert.equal(ops.relationLookup('other', ops.capture(a)).status, 'not-found')
  })
  test('文件 UUID 解析、文件入口注册和函数入口独立', () => {
    const node = { type: 'CompileUnit', body: [first.ast.node], loc: loc('/virtual/a.py', 1) }
    const file = { vtype: 'scope', ast: { node }, value: {} }
    analyzer.fileManager = { '/virtual/a.py': { uuid: 'symuuid_file', astNode: node } }
    analyzer.symbolTable.set('symuuid_file', file)
    const fileCandidate = one(ops.scanSymbols('file'))
    assert.equal(one(ops.registerEntryPoint(fileCandidate, { kind: 'file' })).outcome, 'registered')
    assert.equal(one(ops.registerEntryPoint(fileCandidate, { kind: 'file' })).outcome, 'duplicate')
    assert.equal(ops.scanDefinitions(undefined, 'function').values.length, 1)
  })
  test('嵌套定义扫描不沿 parent 回环，方法枚举不包含内部函数', () => {
    const method = definition('method')
    const nested = definition('nested')
    method.body = [nested]
    const cls: any = { type: 'ClassDefinition', id: { name: 'Fixture' }, body: [method] }
    method.parent = cls
    const h = ops.capture(cls)
    assert.equal(ops.scanDefinitions(h, 'function').values.length, 2)
    assert.deepEqual(
      ops.getMethods(h).values.map((v) => ops.readMetadata(v).name),
      ['method']
    )
  })
  test('AST 关键字参数、别名和装饰器数据可查询但不执行', () => {
    const deco = {
      type: 'CallExpression',
      callee: {
        type: 'MemberAccess',
        object: { type: 'Identifier', name: 'app' },
        property: { type: 'Identifier', name: 'route' },
      },
      arguments: [{ type: 'VariableDeclaration', id: { name: 'fn' }, init: { type: 'Identifier', name: 'callback' } }],
    }
    const node = definition('decorated')
    node._meta = { decorators: [deco] }
    const metadata = ops.readMetadata(ops.capture(node))
    const view = one(ops.readCall(metadata.decorators[0]))
    assert.equal(view.arguments[0].name, 'fn')
    assert.equal(view.arguments[0].evaluated, false)
    assert.equal(ops.readMetadata(view.callee).name, 'route')
    const unit = {
      type: 'CompileUnit',
      body: [
        {
          type: 'VariableDeclaration',
          id: { name: 'Alias' },
          init: { type: 'ImportExpression', from: { value: 'package' }, imported: { name: 'Factory' } },
        },
      ],
    }
    assert.deepEqual(one(ops.readImports(ops.capture(unit))), {
      local: 'Alias',
      imported: 'Factory',
      module: 'package',
    })
  })
  test('Python httpserver：与现有 collector 核对方法位置，不只比较数量', () => {
    const file = '/virtual/handler.py'
    const method = definition('do_POST', file, 4)
    const clsNode = {
      type: 'ClassDefinition',
      id: { name: 'Fixture' },
      supers: [{ type: 'Identifier', name: 'BaseHTTPRequestHandler' }],
      body: [method],
    }
    const cls: any = { vtype: 'class', ast: { node: clsNode }, value: { vtype: 'object', value: {} } }
    cls.value.value.do_POST = fn(method, cls)
    const localAnalyzer: any = {
      topScope: { context: { modules: { vtype: 'scope', value: { Fixture: cls } } } },
      entryPoints: [],
    }
    const lib = new GenericEntryPointOperators(localAnalyzer)
    const resolved = one(lib.resolveClass(lib.capture(cls)))
    assert.deepEqual(lib.getBaseTypes(resolved).values, ['BaseHTTPRequestHandler'])
    const selected = one(lib.filterCandidates(lib.getMethods(resolved).values, (m) => m.name === 'do_POST'))
    one(lib.registerEntryPoint(selected))
    const collector = require('../../engine/analyzer/python/httpserver/entrypoint-collector/httpserver-entrypoint')
    const expected = collector.findHttpServerEntryPointAndSource({ [file]: { body: [clsNode] } }, '/virtual/')
      .httpServerEntryPointArray[0]
    assert.equal(localAnalyzer.entryPoints[0].functionName, expected.functionName)
    assert.equal(localAnalyzer.entryPoints[0].funcLocStart, expected.funcLocStart)
    assert.equal(localAnalyzer.entryPoints[0].funcReceiverType, expected.funcReceiverType)
  })
  test('Java Spring：真实 ValueRefMap 适配与现有注解 collector 一致', () => {
    const { ValueRefMap } = require('../../engine/analyzer/common/value/value-ref-map')
    const members = new ValueRefMap(() => null)
    const method = definition('endpoint', '/virtual/Fixture.java', 8)
    method._meta = { modifiers: ['@GetMapping'] }
    const cls: any = { vtype: 'class', members, ast: { node: { type: 'ClassDefinition', id: { name: 'Fixture' } } } }
    const closure = fn(method, cls)
    members.set('endpoint', closure)
    const packages = { vtype: 'package', members: new Map([['Fixture', cls]]) }
    const collector = require('../../engine/analyzer/java/spring/entrypoint-collector/spring-default-entrypoint')
    const expected = collector.getSpringEntryPointAndSource(packages).selfCollectSpringEntryPoints
    const localAnalyzer: any = { entryPoints: [], topScope: { context: { packages } } }
    const lib = new GenericEntryPointOperators(localAnalyzer)
    const matches = lib.filterCandidates(lib.scanSymbols('function').values, (m) => m.modifiers.includes('@GetMapping'))
    one(lib.registerEntryPoint(one(matches)))
    assert.equal(localAnalyzer.entryPoints[0].entryPointSymVal, expected[0])
    assert.equal(localAnalyzer.entryPoints[0].funcLocStart, 8)
  })
  test('Go main：与现有符号扫描 collector 一致，独立 main 容器', () => {
    const main = fn(definition('main', '/virtual/main.go'))
    const packages = { vtype: 'package', _field: { main } }
    const collector = require('../../engine/analyzer/golang/common/entrypoint-collector/go-default-entrypoint')
    const expected = collector.getMainEntryPoints(packages)
    const localAnalyzer: any = { topScope: { context: { packages } } }
    const lib = new GenericEntryPointOperators(localAnalyzer)
    const selected = one(lib.filterCandidates(lib.scanSymbols('function').values, (m) => m.name === 'main'))
    one(lib.registerEntryPoint(selected, { destination: 'mainEntryPoints', attribute: 'program' }))
    assert.equal(localAnalyzer.mainEntryPoints[0].entryPointSymVal, expected[0])
    assert.equal(localAnalyzer.entryPoints, undefined)
  })
  test('PHP MVC：moduleScopes / ast.cdef / value 方法与 collector 一致', () => {
    const file = '/virtual/Fixture.php'
    const method = definition('action', file, 5)
    method.parameters = [{ id: { name: 'request' } }]
    method.modifiers = ['public']
    const cdef = { type: 'ClassDefinition', id: { name: 'FixtureController' }, body: [method], supers: [] }
    const cls: any = { vtype: 'class', ast: { cdef }, value: {} }
    cls.value.action = fn(method, cls)
    const localAnalyzer: any = {
      entryPoints: [],
      moduleScopes: new Map([[file, { value: { FixtureController: cls } }]]),
    }
    const lib = new GenericEntryPointOperators(localAnalyzer)
    const selected = one(
      lib.filterCandidates(
        lib.getMethods(one(lib.scanSymbols('class'))).values,
        (m) => m.parameters.length >= 1 && !m.modifiers.includes('private')
      )
    )
    one(lib.registerEntryPoint(selected))
    const collector = require('../../engine/analyzer/php/custom/entrypoint-collector/custom-mvc-controller-entrypoint')
    const expected = collector.findCustomMvcControllerEntryPoints(localAnalyzer, '/virtual/')
    assert.equal(localAnalyzer.entryPoints[0].entryPointSymVal, expected[0].entryPointSymVal)
  })
  test('CHA 委托不按类短名猜测，无能力明确 unsupported', () => {
    const type = { vtype: 'class', qid: 'pkg.Fixture', ast: { node: { type: 'ClassDefinition' } } }
    assert.equal(ops.getSubTypes(ops.capture(type)).status, 'unsupported')
    const hierarchy = {}
    const lib = new GenericEntryPointOperators({
      typeResolver: {
        classHierarchyMap: new Map([['pkg.Fixture', hierarchy]]),
        findSubTypes: (h: unknown) => {
          assert.equal(h, hierarchy)
          return ['pkg.Implementation']
        },
        findBaseTypes: () => ['pkg.Base'],
      },
    })
    assert.deepEqual(lib.getSubTypes(lib.capture(type)).values, ['pkg.Implementation'])
    assert.deepEqual(lib.getBaseTypes(lib.capture(type), true).values, ['pkg.Base'])
  })
  test('调用图仅查询已有状态，不调用建图/执行函数', () => {
    assert.equal(ops.queryGraphEntries({ kind: 'roots' }).status, 'unsupported')
    const graph = {
      nodes: new Map([['root', { id: 'root', opts: { funcDef: first.ast.node, funcSymbol: first } }]]),
      edges: new Map(),
    }
    const lib = new GenericEntryPointOperators({ ainfo: { callgraph: graph } })
    assert.equal(lib.readMetadata(one(lib.queryGraphEntries({ kind: 'roots' }))).name, 'callback')
  })
  test('FrameworkSpec v2：Modeler 计划经 Generic 流水线注册真实入口', () => {
    const main = fn(definition('main', '/virtual/connected.go'))
    const packages = { vtype: 'package', _field: { main } }
    const manager = { checkpoints: { check_at_start_analyze: [] as unknown[] } }
    const localAnalyzer: any = {
      topScope: { context: { packages } },
      getCheckerManager: () => manager,
    }
    const spec: FrameworkSpec = {
      schemaVersion: 2,
      checkerId: 'meta_connection_test',
      framework: 'fixture',
      language: 'golang',
      entryPointPlans: [
        {
          id: 'program-entry',
          trigger: 'startOfAnalyze',
          steps: [
            { id: 'functions', operator: 'scanSymbols', options: { kind: 'function' } },
            {
              id: 'named-entry',
              operator: 'filterCandidates',
              options: {
                conditions: {
                  all: [{ field: 'name', operator: 'equals', value: 'main' }],
                },
              },
            },
            { id: 'resolved', operator: 'resolveFunction' },
            {
              id: 'registered',
              operator: 'registerEntryPoint',
              options: {
                attribute: 'program',
                destination: 'mainEntryPoints',
              },
            },
          ],
        },
      ],
    }
    const checker = new GenericFrameworkChecker({}, spec)
    assert(checker.getSubscriptions().includes('compileUnit'))
    checker.triggerAtCompileUnit(localAnalyzer, null, { type: 'CompileUnit' }, null, null)
    assert(manager.checkpoints.check_at_start_analyze.includes(checker))
    checker.triggerAtStartOfAnalyze(localAnalyzer, null, null, null, null)
    assert.equal(localAnalyzer.mainEntryPoints.length, 1)
    assert.equal(localAnalyzer.mainEntryPoints[0].entryPointSymVal, main)
    assert.equal(localAnalyzer.mainEntryPoints[0].framework, 'fixture')
  })
  test('句柄隔离与 reset，不能跨分析复用关系', () => {
    const old = ops.capture(first)
    assert.throws(() => new GenericEntryPointOperators({}).readMetadata(old), /不属于当前分析/)
    const before = analyzer.entryPoints.length
    ops.reset()
    assert.throws(() => ops.readMetadata(old), /不属于当前分析/)
    assert.equal(analyzer.entryPoints.length, before)
  })
  return { passed: cases.length, cases }
}

module.exports.testEntryPointOperators = testEntryPointOperators
