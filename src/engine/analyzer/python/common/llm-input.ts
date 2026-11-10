import fs from 'fs'
import path from 'path'
import { createHash } from 'crypto'
import { buildNewCopiedWithTag, lodashCloneWithTag } from '../../../../util/clone-util'
import type { CallInfo } from '../../common/call-args'

const EntryPoint = require('../../common/entrypoint/entrypoint')
const Constant = require('../../../../util/constant')
const { markTaintSource } = require('../../../../checker/taint/common-kit/source-util')
const CurrentEntryPoint = require('../../common/entrypoint/current-entrypoint')
const logger = require('../../../../util/logger')(__filename)
const TaintChecker = require('../../../../checker/taint/taint-checker')
const SanitizerChecker = require('../../../../checker/sanitizer/sanitizer-checker')
const TaintOutputStrategy = require('../../../../checker/common/output/taint-output-strategy')
const { addMatchedSinkCount } = require('../../../../checker/taint/common-kit/sink-util')

interface Location {
  file: string
  start_line: number
  start_column?: number
  end_line: number
  end_column?: number
  start_column_utf8?: number
  end_column_utf8_exclusive?: number
}

interface ImportedEntry {
  case_id: string
  name: string
  function: string
  location: Location
  skip_decorators: boolean
  verdict: { is_entrypoint: boolean }
}

interface ImportedSource {
  candidate_id: string
  case_id: string
  syntax_kind: string
  expression: string
  choice: string
  location: Location
  owner_location: Location
}

interface Input {
  schema: string
  language: string
  mode: string
  files: { file: string; sha256: string }[]
  entrypoints: ImportedEntry[]
  sources: ImportedSource[]
  sinks: ImportedSink[]
}

interface ImportedSinkArgument {
  selector: string
  kind: string
  source_index?: number
  name?: string | null
  expression: string
  location: Location
}

interface ImportedSink {
  candidate_id: string
  location: Location
  callee: string
  expression: string
  verdict: {
    is_sink: boolean
    sink_kind: string
    dangerous_arguments: ImportedSinkArgument[]
    [key: string]: unknown
  }
}

interface SinkState {
  sink: ImportedSink
  astMatched: boolean
  visits: number
  arguments: { argument: ImportedSinkArgument; checks: number; unresolved: number; findings: number }[]
}

/** Frozen model decisions, resolved by definition and expression locations.
 * No framework recognizer, source-name heuristic or confidence threshold here.
 */
export class PythonLlmInput {
  readonly input: Input
  private sourcesByPosition = new Map<string, ImportedSource[]>()
  private sourceState = new Map<string, { source: ImportedSource; astMatched: boolean; visits: number; marks: number }>()
  private bindings: { case_id: string; function: string; status: string; reason?: string }[] = []
  private boundEntries: any[] = []
  private sequence = 0
  private active = false
  private sinksByPosition = new Map<string, SinkState>()
  private sinkChecker: any

  constructor(readonly filename: string, readonly root: string, readonly reportDir?: string) {
    this.root = fs.realpathSync(root)
    this.input = JSON.parse(fs.readFileSync(filename, 'utf8')) as Input
    const input = this.input
    if (input.schema !== 'yasa-llm-input/v2' || input.language !== 'python' || input.mode !== 'replace') {
      throw new Error('Expected yasa-llm-input/v2 with imported entrypoints, sources and sinks; re-export old v1 inputs')
    }
    if (!Array.isArray(input.files) || !Array.isArray(input.entrypoints) || !Array.isArray(input.sources) || !Array.isArray(input.sinks)) {
      throw new Error('Invalid LLM input arrays')
    }
    const files = new Set<string>()
    for (const file of input.files) {
      const absolute = this.resolveFile(file.file)
      const actual = createHash('sha256').update(fs.readFileSync(absolute)).digest('hex')
      if (actual !== file.sha256) throw new Error(`LLM input source changed: ${file.file}`)
      if (files.has(file.file)) throw new Error(`Duplicate LLM file: ${file.file}`)
      files.add(file.file)
    }
    const cases = new Set<string>()
    const definitions = new Set<string>()
    for (const entry of input.entrypoints) {
      this.validateLocation(entry.location, files)
      const definition = this.locationKey(entry.location)
      if (!entry.case_id || !entry.name || entry.verdict?.is_entrypoint !== true ||
          typeof entry.skip_decorators !== 'boolean' || cases.has(entry.case_id) || definitions.has(definition)) {
        throw new Error(`Invalid/duplicate model entrypoint: ${entry.case_id}`)
      }
      cases.add(entry.case_id)
      definitions.add(definition)
    }
    for (const source of input.sources) {
      this.validateLocation(source.location, files)
      this.validateLocation(source.owner_location, files)
      if (source.choice !== 'yes' || !cases.has(source.case_id) || !source.candidate_id ||
          !['parameter', 'call_return', 'attribute_read', 'subscript_read'].includes(source.syntax_kind)) {
        throw new Error(`Invalid model source: ${source.candidate_id}`)
      }
      const id = this.sourceId(source)
      if (this.sourceState.has(id)) throw new Error(`Duplicate model source: ${id}`)
      this.sourceState.set(id, { source, astMatched: false, visits: 0, marks: 0 })
      const key = this.locationKey(source.location)
      const bucket = this.sourcesByPosition.get(key) || []
      bucket.push(source)
      this.sourcesByPosition.set(key, bucket)
    }
    for (const sink of input.sinks) {
      this.validateLocation(sink.location, files)
      this.sinksByPosition.set(this.locationKey(sink.location), {
        sink, astMatched: false, visits: 0,
        arguments: sink.verdict.dangerous_arguments.map(argument => ({ argument, checks: 0, unresolved: 0, findings: 0 })),
      })
    }
  }

  private resolveFile(file: string): string {
    if (typeof file !== 'string' || path.isAbsolute(file) || file.split(/[\\/]/).includes('..')) {
      throw new Error(`LLM paths must be repository-relative: ${file}`)
    }
    const absolute = fs.realpathSync(path.resolve(this.root, file))
    const relative = path.relative(this.root, absolute)
    if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) throw new Error(`LLM path outside repository: ${file}`)
    return absolute
  }

  private validateLocation(loc: Location, files: Set<string>): void {
    if (!loc || !files.has(loc.file) || !Number.isInteger(loc.start_line) ||
        !Number.isInteger(loc.end_line) || loc.start_line < 1 || loc.end_line < loc.start_line ||
        !Number.isInteger(loc.start_column_utf8 ?? loc.start_column) ||
        !Number.isInteger(loc.end_column_utf8_exclusive ?? loc.end_column) ||
        (loc.start_column_utf8 ?? loc.start_column ?? 0) < 1 ||
        (loc.end_column_utf8_exclusive ?? loc.end_column ?? 0) < 1) {
      throw new Error('Invalid LLM source/definition location')
    }
  }

  private sourceId(source: ImportedSource): string {
    return `${source.case_id}:${source.candidate_id}`
  }

  private locationKey(loc: Location): string {
    return `${path.resolve(this.root, loc.file)}:${loc.start_line}:${loc.start_column_utf8 ?? loc.start_column}:${loc.end_line}:${loc.end_column_utf8_exclusive ?? loc.end_column}`
  }

  private nodeKey(node: any): string | undefined {
    const loc = node?.loc
    if (!loc?.sourcefile || !loc.start || !loc.end) return undefined
    return `${path.resolve(loc.sourcefile)}:${loc.start.line}:${loc.start.column}:${loc.end.line}:${loc.end.column}`
  }

  private sourceMatchesNode(source: ImportedSource, node: any): boolean {
    if (source.syntax_kind === 'parameter') return node.type === 'Identifier'
    if (source.syntax_kind === 'call_return') return node.type === 'CallExpression' || node.type === 'NewExpression'
    // uast4py also emits computed=false for string-literal subscripts. The
    // frozen Python-AST syntax kind and exact span disambiguate these reads.
    return node.type === 'MemberAccess'
  }

  /** Resolve original definitions, including nested functions and overloads. */
  bind(analyzer: any): void {
    const nodes = new Map<string, any>()
    const seen = new Set<object>()
    const walk = (node: any): void => {
      if (!node || typeof node !== 'object' || seen.has(node)) return
      seen.add(node)
      if (node.type) {
        const key = this.nodeKey(node)
        if (key) {
          if (['FunctionDefinition', 'ClassDefinition', 'CompileUnit'].includes(node.type)) nodes.set(key, node)
          for (const source of this.sourcesByPosition.get(key) || []) {
            if (this.sourceMatchesNode(source, node)) this.sourceState.get(this.sourceId(source))!.astMatched = true
          }
          const sink = this.sinksByPosition.get(key)
          if (sink && ['CallExpression', 'NewExpression'].includes(node.type)) sink.astMatched = true
        }
      }
      if (Array.isArray(node)) node.forEach(walk)
      else for (const [key, value] of Object.entries(node)) {
        if (!['parent', 'loc', '_meta'].includes(key)) walk(value)
      }
    }
    for (const file of Object.values(analyzer.fileManager || {}) as any[]) walk(file.astNode)
    const closures = new Map<string, any>()
    for (const value of analyzer.symbolTable.getMap().values()) {
      if (!['fclos', 'class', 'module', 'package'].includes(value?.vtype)) continue
      const key = this.nodeKey(value.ast?.node)
      if (key && !closures.has(key)) closures.set(key, value)
      if (value.vtype === 'fclos') {
        for (let i = 0; i < (value.overloaded?.length || 0); i++) {
          const definition = value.overloaded.get ? value.overloaded.get(i) : value.overloaded[i]
          const overloadKey = this.nodeKey(definition)
          if (overloadKey && !closures.has(overloadKey)) {
            const copy = lodashCloneWithTag(value)
            copy.ast = definition
            copy.ast.fdef = definition
            closures.set(overloadKey, copy)
          }
        }
      }
    }
    const resolve = (node: any): any => {
      const key = this.nodeKey(node)
      if (!key) return undefined
      if (closures.has(key)) return closures.get(key)
      if (node.type === 'CompileUnit') {
        const module = analyzer.topScope.context.modules.members.get(node.loc.sourcefile)
        if (module) closures.set(key, module)
        return module
      }
      let parent = node.parent
      while (parent && !['FunctionDefinition', 'ClassDefinition', 'CompileUnit'].includes(parent.type)) parent = parent.parent
      const scope = parent && resolve(parent)
      if (!scope || node.type !== 'FunctionDefinition') return undefined
      // Materialize the lexical function scope without running its enclosing
      // factory/registration code or treating that factory as another entrypoint.
      const closure = analyzer.createFuncScope(node, scope)
      closures.set(key, closure)
      return closure
    }
    for (const entry of this.input.entrypoints) {
      const node = nodes.get(this.locationKey(entry.location))
      const closure = node?.type === 'FunctionDefinition' && node.id?.name === entry.name ? resolve(node) : undefined
      if (!closure || closure.vtype !== 'fclos') {
        this.bindings.push({ case_id: entry.case_id, function: entry.function, status: 'unmatched', reason: 'Exact function definition/scope unavailable' })
        continue
      }
      const exactClosure = lodashCloneWithTag(closure)
      exactClosure.ast = node
      exactClosure.ast.fdef = node
      exactClosure.overloaded = [] // Never execute sibling definitions as implicit entries.
      const ep = new EntryPoint(Constant.ENGIN_START_FUNCALL)
      ep.filePath = `/${entry.location.file}`
      ep.functionName = entry.name
      ep.funcLocStart = entry.location.start_line
      ep.funcLocEnd = entry.location.end_line
      ep.entryPointSymVal = exactClosure
      ep.scopeVal = exactClosure.parent
      ep.skipDecorators = entry.skip_decorators
      ep.llmCaseId = entry.case_id
      ep.llmPrediction = entry
      ep.attribute = `LLM:${entry.case_id}`
      this.boundEntries.push(ep)
      this.bindings.push({ case_id: entry.case_id, function: entry.function, status: 'matched' })
    }
    analyzer.entryPoints = this.boundEntries.slice()
    this.sinkChecker = new TaintChecker(analyzer.checkerManager.getResultManager(), 'taint_flow_python_llm_input')
    this.active = true
    this.writeDiagnostics()
    logger.info(`[LLM] Imported entrypoints: ${this.boundEntries.length}/${this.input.entrypoints.length}; source decisions: ${this.input.sources.length}; sink decisions: ${this.input.sinks.length}; native entrypoint/source/sink rules replaced`)
    const matchedSources = [...this.sourceState.values()].filter(s => s.astMatched).length
    logger.info(`[LLM] Source positions matched to UAST: ${matchedSources}/${this.input.sources.length}`)
    logger.info(`[LLM] Sink positions matched to UAST: ${[...this.sinksByPosition.values()].filter(s => s.astMatched).length}/${this.input.sinks.length}; without selected arguments: ${[...this.sinksByPosition.values()].filter(s => s.arguments.length === 0).length}`)
    if (this.bindings.some(b => b.status === 'unmatched') || matchedSources !== this.input.sources.length) {
      logger.warn('[LLM] Some imported positions could not be bound; see llm-input-diagnostics.json; no name-based fallback was applied')
    }
    if (this.input.entrypoints.length > 0 && this.boundEntries.length === 0) throw new Error('No imported LLM entrypoint could be bound; see llm-input-diagnostics.json')
  }

  mark(analyzer: any, node: any, value: any, parameter = false): any {
    if (!this.active || analyzer.preprocessState) return value
    const key = this.nodeKey(node)
    if (!key) return value
    const caseId = CurrentEntryPoint.getCurrentEntryPoint()?.llmCaseId
    const sources = (this.sourcesByPosition.get(key) || []).filter(source =>
      source.case_id === caseId && (source.syntax_kind === 'parameter') === parameter && this.sourceMatchesNode(source, node))
    if (sources.length === 0) return value
    for (const source of sources) this.sourceState.get(this.sourceId(source))!.visits++
    if (!value?.taint) return value
    // Isolate the returned value: a global framework object must not acquire
    // model source tags that leak into subsequent entrypoint executions.
    const result = buildNewCopiedWithTag(analyzer, value, `llm_source_${++this.sequence}`)
    markTaintSource(result, { path: node, kind: 'PYTHON_INPUT', replaceInheritedSource: true, origin: 'llm' })
    for (const source of sources) {
      const state = this.sourceState.get(this.sourceId(source))!
      if (result.taint.containsTag('PYTHON_INPUT')) state.marks++
    }
    return result
  }

  checkSink(analyzer: any, node: any, fclos: any, callInfo: CallInfo, state: any): void {
    if (!this.active || analyzer.preprocessState) return
    const key = this.nodeKey(node)
    const sinkState = key && this.sinksByPosition.get(key)
    if (!sinkState) return
    sinkState.visits++
    addMatchedSinkCount(1)
    for (const selected of sinkState.arguments) {
      const { argument } = selected
      const args = callInfo.callArgs?.args || []
      let value: any
      if (argument.kind === 'receiver') {
        value = callInfo.callArgs?.receiver
      } else if (argument.kind === 'keyword') {
        value = args.find(arg => arg.kind === 'keyword' && arg.name === argument.name)?.value
      } else if (argument.kind === 'positional') {
        const arg = args.filter(arg => arg.kind === 'positional' || arg.kind === 'spread')[argument.source_index!]
        if (arg?.kind === 'positional' && this.nodeKey(arg.node) === this.locationKey(argument.location)) value = arg.value
      }
      // Unresolved *args/**kwargs and missing bindings remain untested, not safe.
      if (value === undefined) {
        selected.unresolved++
        continue
      }
      selected.checks++
      const matches = SanitizerChecker.findTagAndMatchedSanitizer(node, fclos, [value], null, 'PYTHON_INPUT', true, [])
      for (const { nd, matchedSanitizerTags } of matches) {
        const sink = sinkState.sink
        const finding = this.sinkChecker.buildTaintFinding(
          'taint_flow_python_llm_input', 'Imported source reaches an LLM-selected sink argument', node, nd, fclos,
          'PYTHON_INPUT', `${sink.callee}\nSINK Attribute: LLM:${sink.verdict.sink_kind}`,
          matchedSanitizerTags, state?.callstack, state?.callsites
        )
        if (!finding) continue
        finding.issuecause = `${sink.candidate_id}:${argument.selector}`
        finding.sinkInfo.llm = { candidate_id: sink.candidate_id, location: sink.location,
          expression: sink.expression, verdict: sink.verdict, argument }
        if (!TaintOutputStrategy.isNewFinding(this.sinkChecker.resultManager, finding)) continue
        this.sinkChecker.resultManager.newFinding(finding, TaintOutputStrategy.outputStrategyId)
        selected.findings++
      }
    }
  }

  finish(analyzer: any): void {
    // Native collectors may still observe calls while sink checkers run. Their
    // appended candidates never become imported entrypoints or affect counts.
    analyzer.entryPoints = this.boundEntries.slice()
    this.active = false
    this.writeDiagnostics()
    const states = [...this.sourceState.values()]
    const sinks = [...this.sinksByPosition.values()]
    logger.info(`[LLM] Source decisions executed: ${states.filter(s => s.visits > 0).length}/${states.length}; marked: ${states.filter(s => s.marks > 0).length}/${states.length}; unexecuted positions remain in llm-input-diagnostics.json`)
    logger.info(`[LLM] Sink decisions executed: ${sinks.filter(s => s.visits > 0).length}/${sinks.length}; arguments checked: ${sinks.reduce((sum, s) => sum + s.arguments.filter(a => a.checks > 0).length, 0)}; native sink rules disabled`)
  }

  writeDiagnostics(): void {
    if (!this.reportDir) return
    fs.mkdirSync(this.reportDir, { recursive: true })
    const states = [...this.sourceState.values()]
    const sinks = [...this.sinksByPosition.values()]
    fs.writeFileSync(path.join(this.reportDir, 'llm-input-diagnostics.json'), JSON.stringify({
      schema: 'yasa-llm-diagnostics/v1', input_file: path.resolve(this.filename), mode: 'replace',
      entrypoints_imported: this.input.entrypoints.length, entrypoints_bound: this.boundEntries.length,
      entrypoints_unmatched: this.bindings.filter(b => b.status === 'unmatched').length,
      source_decisions_imported: states.length, source_decisions_ast_matched: states.filter(s => s.astMatched).length,
      source_decisions_executed: states.filter(s => s.visits > 0).length,
      source_decisions_marked: states.filter(s => s.marks > 0).length,
      source_mark_events: states.reduce((sum, s) => sum + s.marks, 0),
      sinks_imported: sinks.length, sinks_ast_matched: sinks.filter(s => s.astMatched).length,
      sinks_executed: sinks.filter(s => s.visits > 0).length,
      sinks_without_selected_arguments: sinks.filter(s => s.arguments.length === 0).length,
      sink_arguments_checked: sinks.reduce((sum, s) => sum + s.arguments.filter(a => a.checks > 0).length, 0),
      sink_arguments_unresolved: sinks.reduce((sum, s) => sum + s.arguments.filter(a => a.unresolved > 0).length, 0),
      sink_finding_events: sinks.reduce((sum, s) => sum + s.arguments.reduce((n, a) => n + a.findings, 0), 0),
      sink_detection: 'imported_positions_and_arguments_only',
      entrypoints: this.bindings, sources: states, sinks,
    }, null, 2) + '\n')
  }
}
