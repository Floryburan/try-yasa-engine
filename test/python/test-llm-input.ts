import * as assert from 'assert'
import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'
import { createHash } from 'crypto'
import { describe, it } from 'mocha'
import { PythonLlmInput } from '../../src/engine/analyzer/python/common/llm-input'

const { execute } = require('../../src/interface/starter')
const { parseSingleFile } = require('../../src/engine/parser/python/python-ast-builder')
const sdk = process.env.YASA_UAST_SDK_PATH || (fs.existsSync(path.resolve(__dirname, '../../deps/uast4py/uast4py'))
  ? path.resolve(__dirname, '../../deps') : path.resolve(__dirname, '../../my-release-bundle/uast4py-linux-amd64'))

const code = `import os
from flask import request

def helper(value):
    os.system(value)

def by_parameter(cmd):
    helper(cmd)

def by_call():
    text = request.args.get("cmd")
    helper(text)

def by_attribute():
    helper(request.form)

def by_subscript():
    helper(request.form["cmd"])

def factory(prefix):
    def callback(path):
        helper(path)
    return callback

class First:
    def handle(self, value):
        helper(value)

class Second:
    def handle(self, value):
        helper(value)

def hide(fn):
    def wrapper(*args, **kwargs):
        return "safe"
    return wrapper

@hide
def decorated(cmd):
    helper(cmd)

def by_helper_parameter():
    helper("runtime input according to imported model")

def no_model_source():
    helper(request.args.get("native-source-must-be-disabled"))

def unselected(cmd):
    helper(cmd)

def selected_keyword(cmd):
    destination(target=cmd)

def selected_constant(cmd):
    two_params("constant", cmd)

def no_imported_sink(cmd):
    os.system(cmd)

def no_selected_argument(cmd):
    pending_sink(cmd)

def selected_receiver(container):
    container.emit("constant")
`

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'yasa-llm-input-'))
  const repo = path.join(root, 'repo')
  fs.mkdirSync(repo)
  fs.writeFileSync(path.join(repo, 'app.py'), code)
  const ast = parseSingleFile(code, { uastSDKPath: sdk })
  const functions: any[] = []
  const calls: any[] = []
  const walk = (node: any): void => {
    if (!node || typeof node !== 'object') return
    if (node.type === 'FunctionDefinition') functions.push(node)
    if (node.type === 'CallExpression' || node.type === 'NewExpression') calls.push(node)
    if (Array.isArray(node)) node.forEach(walk)
    else for (const [key, value] of Object.entries(node)) if (!['loc', '_meta', 'parent'].includes(key)) walk(value)
  }
  walk(ast)
  const fn = (name: string, occurrence = 0) => functions.filter(n => n.id?.name === name)[occurrence]
  const location = (node: any) => ({ file: 'app.py', start_line: node.loc.start.line, start_column: node.loc.start.column,
    end_line: node.loc.end.line, end_column: node.loc.end.column })
  const entries: any[] = []
  const add = (name: string, occurrence = 0) => {
    const node = fn(name, occurrence)
    const caseId = `${name}_${occurrence}`
    entries.push({ case_id: caseId, function: `app.${caseId}`, name, location: location(node),
      skip_decorators: true, verdict: { is_entrypoint: true } })
    return caseId
  }
  const sources: any[] = []
  const source = (caseId: string, owner: any, kind: string, text: string, line: number) => {
    const column = Buffer.byteLength(code.split('\n')[line - 1].split(text)[0], 'utf8') + 1
    sources.push({ candidate_id: `source_${sources.length}`, case_id: caseId, syntax_kind: kind,
      choice: 'yes', expression: text, probabilities: { yes: 0.4, no: 0.3, unknown: 0.3 },
      location: { file: 'app.py', start_line: line, start_column_utf8: column,
        end_line: line, end_column_utf8_exclusive: column + Buffer.byteLength(text, 'utf8') },
      owner_location: location(owner) })
  }
  const parameter = add('by_parameter')
  source(parameter, fn('by_parameter'), 'parameter', 'cmd', fn('by_parameter').loc.start.line)
  const call = add('by_call')
  source(call, fn('by_call'), 'call_return', 'request.args.get("cmd")', fn('by_call').loc.start.line + 1)
  const attr = add('by_attribute')
  source(attr, fn('by_attribute'), 'attribute_read', 'request.form', fn('by_attribute').loc.start.line + 1)
  const sub = add('by_subscript')
  source(sub, fn('by_subscript'), 'subscript_read', 'request.form["cmd"]', fn('by_subscript').loc.start.line + 1)
  const callback = add('callback')
  source(callback, fn('callback'), 'parameter', 'path', fn('callback').loc.start.line)
  const first = add('handle')
  source(first, fn('handle'), 'parameter', 'value', fn('handle').loc.start.line)
  add('handle', 1) // Same name, separate class; no model source here.
  const decorated = add('decorated')
  source(decorated, fn('decorated'), 'parameter', 'cmd', fn('decorated').loc.start.line)
  const viaHelper = add('by_helper_parameter')
  source(viaHelper, fn('helper'), 'parameter', 'value', fn('helper').loc.start.line)
  add('no_model_source')
  for (const name of ['selected_keyword', 'selected_constant', 'no_imported_sink', 'no_selected_argument', 'selected_receiver']) {
    const id = add(name)
    source(id, fn(name), 'parameter', name === 'selected_receiver' ? 'container' : 'cmd', fn(name).loc.start.line)
  }
  const sinks: any[] = []
  const sink = (ownerName: string, kind: string, argumentKind: string | null, argumentText: string) => {
    const line = fn(ownerName).loc.start.line + 1
    const call = calls.find(n => n.loc.start.line === line)
    const lineText = code.split('\n')[line - 1]
    const column = Buffer.byteLength(lineText.slice(0, lineText.indexOf(argumentText)), 'utf8') + 1
    const selector = argumentKind === 'receiver' ? 'receiver' : argumentKind === 'keyword' ? 'keyword_0' : 'positional_0'
    sinks.push({ candidate_id: `sink_${ownerName}`, location: location(call), callee: lineText.trim().split('(')[0],
      expression: lineText.trim(), verdict: { is_sink: true, sink_kind: kind,
        sink_answer: { choice: 'yes', confidence: 0.1, probabilities: { yes: 0.4, no: 0.3, unknown: 0.3 } },
        dangerous_arguments: argumentKind ? [{ selector, kind: argumentKind, source_index: 0,
          name: argumentKind === 'keyword' ? 'target' : null, expression: argumentText,
          location: { file: 'app.py', start_line: line, start_column_utf8: column,
            end_line: line, end_column_utf8_exclusive: column + Buffer.byteLength(argumentText, 'utf8') } }] : [] } })
  }
  sink('helper', 'command_execution', 'positional', 'value')
  sink('selected_keyword', 'other', 'keyword', 'cmd')
  sink('selected_constant', 'other', 'positional', '"constant"')
  sink('no_selected_argument', 'other', null, 'cmd')
  sink('selected_receiver', 'other', 'receiver', 'container')
  const input = { schema: 'yasa-llm-input/v2', language: 'python', mode: 'replace',
    files: [{ file: 'app.py', sha256: createHash('sha256').update(code).digest('hex') }], entrypoints: entries, sources, sinks }
  const inputFile = path.join(root, 'input.json')
  fs.writeFileSync(inputFile, JSON.stringify(input))
  return { root, repo, input, inputFile }
}

describe('Imported model entrypoints and sources', function () {
  this.timeout(60000)

  it('rejects changed sources, duplicate entries and paths outside the repository', () => {
    const f = fixture()
    assert.doesNotThrow(() => new PythonLlmInput(f.inputFile, f.repo))
    fs.appendFileSync(path.join(f.repo, 'app.py'), '# changed\n')
    assert.throws(() => new PythonLlmInput(f.inputFile, f.repo), /source changed/)
    fs.writeFileSync(path.join(f.repo, 'app.py'), code)
    f.input.entrypoints.push(f.input.entrypoints[0])
    fs.writeFileSync(f.inputFile, JSON.stringify(f.input))
    assert.throws(() => new PythonLlmInput(f.inputFile, f.repo), /duplicate model entrypoint/)
    f.input.entrypoints.pop()
    f.input.files[0].file = '../outside.py'
    fs.writeFileSync(f.inputFile, JSON.stringify(f.input))
    assert.throws(() => new PythonLlmInput(f.inputFile, f.repo), /repository-relative/)
  })

  it('executes exactly imported definitions and propagates all four source kinds to a real sink', async () => {
    const f = fixture()
    const report = path.join(f.root, 'report')
    const rules = path.join(f.root, 'rules.json')
    fs.writeFileSync(rules, JSON.stringify([{ checkerIds: ['taint_flow_python_input'],
      sources: { FuncCallReturnValueTaintSource: [{ fsig: 'get', scopeFile: 'all', scopeFunc: 'all' }] },
      entrypoints: [{ filePath: '/app.py', functionName: 'unselected' },
        { filePath: '/app.py', functionName: 'no_model_source' }],
      sinks: { FuncCallTaintSink: [{ fsig: 'os.system', args: ['0'], attribute: 'PythonCommandInjection' }] } }]))
    await execute(null, ['--sourcePath', f.repo, '--analyzer', 'PythonAnalyzer', '--checkerIds', 'taint_flow_python_input',
      '--ruleConfigFile', rules, '--report', report, '--llmInputFile', f.inputFile,
      '--entrypointMode', 'BOTH', '--uastSDKPath', sdk], () => {})
    const diagnostics = JSON.parse(fs.readFileSync(path.join(report, 'llm-input-diagnostics.json'), 'utf8'))
    assert.strictEqual(diagnostics.entrypoints_imported, 15)
    assert.strictEqual(diagnostics.entrypoints_bound, 15)
    assert.strictEqual(diagnostics.entrypoints_unmatched, 0)
    assert.strictEqual(diagnostics.source_decisions_ast_matched, 13)
    assert.strictEqual(diagnostics.source_decisions_marked, 13)
    assert.strictEqual(diagnostics.sinks_ast_matched, 5)
    assert.strictEqual(diagnostics.sinks_without_selected_arguments, 1)
    const sarif = JSON.parse(fs.readFileSync(path.join(report, 'report.sarif'), 'utf8'))
    const results = sarif.runs.flatMap((run: any) => run.results || [])
    assert.strictEqual(results.length, 10, 'Only imported sink arguments receive imported sources, including keyword and receiver selections')
    const names = results.map((r: any) => r.entrypoint.functionName)
    assert.ok(names.includes('callback'), 'Nested entrypoint must execute without selecting its factory')
    assert.ok(names.includes('decorated'), 'Original decorated body must execute')
    assert.ok(!names.includes('no_model_source'))
    assert.ok(!names.includes('unselected'))
    assert.ok(names.includes('selected_keyword'), 'A sink absent from native rules must produce a finding')
    assert.ok(names.includes('selected_receiver'))
    assert.ok(!names.includes('selected_constant'), 'Taint in an unselected argument must not trigger the selected constant argument')
    assert.ok(!names.includes('no_imported_sink'), 'A native os.system rule cannot add an unimported sink')
    assert.ok(!names.includes('no_selected_argument'), 'Missing model argument selections must not fall back to native/all-argument matching')
    assert.strictEqual(names.filter((n: string) => n === 'handle').length, 1)
    for (const result of results) {
      const trace = JSON.stringify(result.codeFlows)
      assert.ok(trace.includes('SOURCE: '), 'Findings retain standard YASA SOURCE traces')
      assert.ok(result.sinkInfo.llm.candidate_id)
      assert.strictEqual(result.sinkInfo.llm.verdict.sink_answer.confidence, 0.1, 'Original model confidence is preserved')
    }
    // The same process can subsequently run a native scan. The preceding import
    // must not leave the global source guard or forced entrypoint mode enabled.
    const nativeReport = path.join(f.root, 'native-report')
    await execute(null, ['--sourcePath', f.repo, '--analyzer', 'PythonAnalyzer', '--checkerIds', 'taint_flow_python_input',
      '--ruleConfigFile', rules, '--report', nativeReport, '--entrypointMode', 'ONLY_CUSTOM', '--uastSDKPath', sdk], () => {})
    const nativeSarif = JSON.parse(fs.readFileSync(path.join(nativeReport, 'report.sarif'), 'utf8'))
    const nativeResults = nativeSarif.runs.flatMap((run: any) => run.results || [])
    assert.strictEqual(nativeResults.length, 1, 'Without the option, the configured native return source remains effective')
    assert.strictEqual(nativeResults[0].entrypoint.functionName, 'no_model_source')
    assert.ok(!fs.existsSync(path.join(nativeReport, 'llm-input-diagnostics.json')))
  })
})
