/* eslint-disable import/no-commonjs */

const Parser = require('../../engine/parser/parser')
const logger = require('../../util/logger')(__filename)

// ==================== 只需要填写下面三个值 ====================
const API_KEY = 'sk-ad944ec536a94388a6bb7d0a651393ee'
const API_URL = '	https://api.deepseek.com/chat/completions'
const MODEL = '	deepseek-v4-pro'
// ==============================================================

/** 调用 Parser 所需的最小项目信息。 */
export interface FrameworkModelRequest {
  rootDir: string
  language: string
  parserOptions?: Record<string, unknown>
}

/** Parser 生成后，交给 LLM 的最小输入。 */
export interface FrameworkModelInput {
  rootDir: string
  language: string
  uast: unknown
}

/** buildPrompt() 生成的两段 LLM 消息。 */
export interface FrameworkLlmPrompt {
  systemPrompt: string
  userPrompt: string
}

/** 通用 Checker 当前允许订阅的 YASA 触发点。 */
export type FrameworkTrigger =
  | 'startOfAnalyze'
  | 'compileUnit'
  | 'endOfCompileUnit'
  | 'assignment'
  | 'functionCallBefore'
  | 'functionCallAfter'
  | 'memberAccess'

/** 一条匹配条件中的比较方式。path 从 trigger context 开始，例如 node.callee.property.name。 */
export type FrameworkMatchOperator =
  | 'equals'
  | 'notEquals'
  | 'includes'
  | 'startsWith'
  | 'endsWith'
  | 'oneOf'
  | 'exists'

export interface FrameworkMatchCondition {
  path: string
  operator: FrameworkMatchOperator
  value?: unknown
}

/** all 中的条件必须全部成立；any 非空时至少成立一条。 */
export interface FrameworkRuleMatch {
  all?: FrameworkMatchCondition[]
  any?: FrameworkMatchCondition[]
}

/** 通用 Checker 支持的最小动作集合。 */
export type FrameworkActionType = 'registerEntryPoint' | 'markSource' | 'rememberValue'

export interface FrameworkRuleAction {
  type: FrameworkActionType
  /** 动作处理的值在 trigger context 中的位置，例如 info.ret。 */
  target: string
  options?: Record<string, unknown>
}

/** LLM 生成的一条“何时检查、匹配什么、执行什么”规则。 */
export interface FrameworkSemanticRule {
  id: string
  trigger: FrameworkTrigger
  match: FrameworkRuleMatch
  action: FrameworkRuleAction
}

/** LLM 可以编排的入口算子；名称与 GenericEntryPointOperators 的公开方法一致。 */
export type FrameworkEntryPointOperator =
  | 'scanDefinitions'
  | 'scanSymbols'
  | 'readCall'
  | 'readAssignment'
  | 'expandAlternatives'
  | 'readElements'
  | 'readMember'
  | 'readMetadata'
  | 'readImports'
  | 'resolveReference'
  | 'resolveFunction'
  | 'resolveClass'
  | 'getMethods'
  | 'getBaseTypes'
  | 'getSubTypes'
  | 'filterCandidates'
  | 'relationStore'
  | 'relationLookup'
  | 'queryGraphEntries'
  | 'registerEntryPoint'

export type FrameworkCandidateField =
  | 'kind'
  | 'name'
  | 'expression'
  | 'literal'
  | 'file'
  | 'ownerName'
  | 'parameterCount'
  | 'modifier'
  | 'decoratorName'
  | 'decoratorExpression'
  | 'baseType'

/** filterCandidates 使用稳定语义字段，不允许 LLM 读取 vtype/value/ast 等内部布局。 */
export interface FrameworkCandidateCondition {
  field: FrameworkCandidateField
  operator: FrameworkMatchOperator
  value?: unknown
  /** 只对 baseType 有效；true 时使用 analyzer 已有的 CHA。 */
  transitive?: boolean
}

export interface FrameworkCandidateFilter {
  all?: FrameworkCandidateCondition[]
  any?: FrameworkCandidateCondition[]
}

/**
 * 一条线性算子步骤。from 缺省时读取上一步；第一步缺省读取当前 YASA 事件。
 * `$event` 是稳定的事件引用，不是 analyzer 内部字段路径。
 */
export interface FrameworkEntryPointOperatorStep {
  id: string
  operator: FrameworkEntryPointOperator
  from?: '$event' | string
  options?: {
    kind?: 'function' | 'class' | 'file'
    select?: 'callee' | 'receiver' | 'argument' | 'arguments' | 'return' | 'target' | 'assigned'
    index?: number
    name?: string
    argumentKind?: 'positional' | 'keyword' | 'spread' | 'kwspread'
    member?: string
    conditions?: FrameworkCandidateFilter
    transitive?: boolean
    namespace?: string
    keyFrom?: '$event' | string
    queryKind?: 'roots' | 'locations' | 'keywords'
    locations?: unknown[]
    keywords?: string[]
    attribute?: string
    framework?: string
    receiverType?: string
    skipDecorators?: boolean
    isPreProcess?: boolean
    destination?: 'entryPoints' | 'mainEntryPoints' | 'ruleEntrypoints'
  }
}

/** 一组在同一 YASA 事件上顺序执行的入口发现算子。 */
export interface FrameworkEntryPointPlan {
  id: string
  trigger: FrameworkTrigger
  steps: FrameworkEntryPointOperatorStep[]
}

/** LLM 的最终输出，也是通用 Checker 的输入。 */
export interface FrameworkSpec {
  schemaVersion: 1 | 2
  checkerId: string
  framework: string
  language: string
  /** schemaVersion=2 的入口发现计划。 */
  entryPointPlans?: FrameworkEntryPointPlan[]
  /** 旧版 source 规则暂时保留兼容；新入口计划不再依赖运行时裸路径。 */
  rules?: FrameworkSemanticRule[]
}

/** 在正式 analyze 前生成 UAST，并调用 LLM 生成 FrameworkSpec。 */
class FrameworkModeler {
  /**
   * PROMPT 编写入口。
   * 后续调整模型角色、规则说明、输出示例时，只修改这里即可。
   *
   * @param input 项目基本信息和 UAST
   * @returns {FrameworkLlmPrompt} 可交给 LLM API 的 system/user prompt
   */
  private buildPrompt(input: FrameworkModelInput): FrameworkLlmPrompt {
    const systemPrompt = [
      '你是 YASA 的框架语义建模器。',
      '请根据目标项目 UAST 中真实存在的导入、继承、装饰器、注册调用、配置引用和回调关系，生成入口发现计划。',
      'Framework Knowledge 写入筛选条件；符号解析、方法枚举和入口注册只能调用给定的通用算子。',
      '不能生成 TypeScript，不能读取 YASA 内部的 vtype/value/ast/parent/callInfo 字段，不能发明算子。',
      '本阶段只生成 EntryPoint 计划，不生成 source 或 sink 规则。',
      '只返回 JSON，不要返回 Markdown 或额外说明。',
    ].join('\n')

    const userPrompt = [
      `项目语言：${input.language}`,
      `项目目录：${input.rootDir}`,
      `输出格式：
{
  "schemaVersion": 2,
  "checkerId": "描述框架的唯一字符串",
  "framework": "框架名称",
  "language": "目标语言",
  "entryPointPlans": [{
    "id": "计划唯一字符串",
    "trigger": "允许的触发点之一",
    "steps": [{
      "id": "本计划内唯一的步骤名",
      "operator": "允许的算子",
      "from": "$event 或之前的步骤 id；省略表示上一步",
      "options": {}
    }]
  }]
}

trigger：
- startOfAnalyze：模块和符号准备完成后做静态发现，适合装饰器、注解、继承和命名约定。
- compileUnit / endOfCompileUnit：需要逐文件观察或延迟到文件结束。
- assignment：框架把回调写入字段或变量。
- functionCallBefore / functionCallAfter：调用参数注册回调，或调用返回对象后才能确定关系。
- memberAccess：只有读取某成员时才出现证据。不要把一种语义强行统一到某个 trigger。

算子与 options：
- scanDefinitions：扫描 UAST 定义，options.kind=function|class|file。
- scanSymbols：扫描已解析符号，options.kind=function|class|file。
- readCall：读取当前调用；options.select=callee|receiver|argument|arguments|return。
  select=argument 时用 options.index（调用点原始参数编号）或 options.name（关键字参数名）；
  options.argumentKind 可进一步限制 positional|keyword|spread|kwspread。
- readAssignment：options.select=target|assigned；assigned 优先使用已经求值的右值。
- expandAlternatives：展开 union 候选，不展开普通列表。
- readElements：展开一层 list/tuple，保留嵌套集合边界。
- readMember：options.member 指定成员名；不写 value.value 等内部路径。
- resolveReference：把 Identifier/MemberAccess 按当前事件 scope 解析成已有值；不会执行表达式。
- resolveFunction / resolveClass：解析已有函数或类；失败不会按同名对象猜测。
- getMethods：枚举类的直接方法，不创建实例，不自动包含继承方法。
- filterCandidates：options.conditions 使用下述稳定字段筛选，同时保留原候选。
- relationStore：options.namespace 和 keyFrom；把 from 的候选按另一步的对象身份保存。
- relationLookup：options.namespace；以 from 的对象身份取回候选。
- queryGraphEntries：options.queryKind=roots|locations|keywords，并提供 locations 或 keywords；只查询已有调用图。
- registerEntryPoint：统一去重和注册。options 可含 kind=function|file、attribute、framework、receiverType、
  skipDecorators、isPreProcess、destination=entryPoints|mainEntryPoints|ruleEntrypoints。
- readMetadata、readImports、getBaseTypes、getSubTypes 是观察算子；其字符串/记录输出不能继续注册为入口。

filterCandidates 条件格式：
{"all":[{"field":"name","operator":"oneOf","value":["框架方法名"]}],"any":[]}
field 只能是 kind、name、expression、literal、file、ownerName、parameterCount、modifier、
decoratorName、decoratorExpression、baseType。operator 只能是 equals、notEquals、includes、startsWith、
endsWith、oneOf、exists。baseType 可加 transitive=true；传递查询只使用 analyzer 已有的 CHA。

流水线约定：
- 第一步不写 from 时输入是 $event；后续步骤不写 from 时输入是上一步输出。
- from 可写 $event 回到当前事件，也可写之前的步骤 id。引用不存在或候选为空时，本次计划停止。
- 步骤输出是集合；resolve/register 逐个处理，不能选择“第一个同名函数”。
- 确认注册 API 后再取回调：readCall(select=callee) → filterCandidates，
  然后 readCall(from=$event, select=argument) → resolveFunction → registerEntryPoint。
- 装饰器/注解模式：scanDefinitions 或 scanSymbols → 按 decoratorName、
  decoratorExpression 或 modifier 筛选 → resolveFunction → registerEntryPoint。
- 继承/处理类模式：扫描 class → 按 baseType 筛选 → getMethods →
  按框架允许的方法名筛选 → resolveFunction → registerEntryPoint。

限制：
- API、包、基类、装饰器/注解、回调参数位置、允许的方法名属于 Framework Knowledge，必须来自 UAST 证据。
- 不要逐个枚举目标项目的普通业务函数名；应表达它们共同满足的框架关系。
- 不得出现 framework 专用算子，不得输出 target/path、vtype、value、_field、members、ast、parent、fclos、qid。
- 不得让 Generic 执行任意源码、构建调用图、创建实例或猜测继承关系。
- 当前算子不能表达的特殊行为应省略，不能伪造。
- 只组合当前项目所需的最少步骤，不需要把所有算子都用上。

只输出上述 schemaVersion=2 的一个 JSON 对象，不要输出旧 rules 字段。`,
      '目标项目 UAST：',
      JSON.stringify(input.uast, (key, value) => (key === 'parent' ? undefined : value), 2),
    ].join('\n')

    return { systemPrompt, userPrompt }
  }

  /**
   * LLM API 调用入口。
   * 使用 OpenAI-compatible Chat Completions HTTP 接口。
   *
   * @param prompt buildPrompt() 生成的提示词
   * @returns {Promise<unknown>} LLM 的原始响应
   */
  private async callLlmApi(prompt: FrameworkLlmPrompt): Promise<unknown> {
    // 按调试需要写入 error 日志；这些带 LLM 标记的记录不代表调用失败。
    logger.error('[frameworkModeler][LLM] 正在请求，等待回复……')
    const response = await fetch(API_URL.trim(), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${API_KEY.trim()}`,
      },
      body: JSON.stringify({
        model: MODEL.trim(),
        messages: [
          { role: 'system', content: prompt.systemPrompt },
          { role: 'user', content: prompt.userPrompt },
        ],
        temperature: 0,
      }),
    })

    const responseText = await response.text()
    logger.error(`[frameworkModeler][LLM] HTTP ${response.status}，原始响应：\n${responseText}`)

    const responseBody = JSON.parse(responseText) as {
      choices: Array<{ message: { content: string } }>
    }
    const [
      {
        message: { content },
      },
    ] = responseBody.choices
    logger.error(`[frameworkModeler][LLM] 回复正文：\n${content}`)
    return JSON.parse(content)
  }

  /**
   * 解析目标项目，并将生成的 UAST 交给 LLM。
   *
   * @param request 项目目录、语言和可选 Parser 配置
   * @returns {Promise<FrameworkSpec>} LLM 生成的框架 Spec
   */
  async build(request: FrameworkModelRequest): Promise<FrameworkSpec> {
    const parserOptions = {
      ...request.parserOptions,
      language: request.language,
    }
    const uast = await Parser.parseProject(request.rootDir, parserOptions)

    const input: FrameworkModelInput = {
      rootDir: request.rootDir,
      language: request.language,
      uast,
    }
    const prompt = this.buildPrompt(input)
    const output = await this.callLlmApi(prompt)
    return output as FrameworkSpec
  }
}

module.exports = FrameworkModeler
