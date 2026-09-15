const JavaTaintAbstractChecker = require("./taint/java/java-taint-abstract-checker")
const EntryPoint = require("../engine/analyzer/common/entrypoint/entrypoint")
const constValue = require("../util/constant")
const Rules = require("./common/rules-basic-handler")

/**
 * Java Spring MVC framework checker.
 *
 * Evidence from the project UAST and reference sources:
 *   - Spring annotations are imported from `org.springframework.web.bind.annotation`
 *     (e.g. `GetMapping`, `RestController`, `RequestParam`). The UAST represents
 *     imports as `VariableDeclaration` nodes whose `init` is an `ImportExpression`
 *     with `from.value` = package and `local.name` = imported symbol.
 *   - Controller classes carry the `@RestController` annotation; the annotation is
 *     materialized under `ClassDefinition._meta.annotations` as a `VariableDeclaration`
 *     whose `id.name` is the annotation simple name (e.g. `RestController`).
 *   - Handler methods carry mapping annotations (`@GetMapping`, `@PostMapping`, ...)
 *     exposed in `FunctionDefinition._meta.modifiers` as strings like `"@GetMapping(\"/search\")"`
 *     and in `_meta.is@GetMapping("/search")`. The method parameter annotated with
 *     `@RequestParam` is the HTTP request input.
 *
 * Scope of this checker:
 *   - Entry point discovery: methods annotated with Spring mapping annotations inside
 *     classes annotated with `@RestController`/`@Controller` are registered as entry points.
 *   - Taint source: parameters of those handler methods are marked as JAVA_INPUT sources.
 *
 * Not verified / intentionally omitted:
 *   - Sink rules are not hardcoded here; they are expected to come from the checker
 *     rule config content loaded by the base class (checkerRuleConfigContent.sinks).
 *   - `@RequestParam` argument binding semantics (required/name) are not modeled; the
 *     whole annotated parameter is treated as a source.
 */

const SPRING_WEB_ANNOTATION_PACKAGE = 'org.springframework.web.bind.annotation'
const SPRING_STEREOTYPE_PACKAGE = 'org.springframework.stereotype'

const SPRING_MAPPING_ANNOTATIONS = new Set([
  'RequestMapping',
  'GetMapping',
  'PostMapping',
  'PutMapping',
  'DeleteMapping',
  'PatchMapping',
])

const SPRING_CONTROLLER_ANNOTATIONS = new Set(['RestController', 'Controller'])

const SPRING_REQUEST_PARAM_ANNOTATIONS = new Set([
  'RequestParam',
  'PathVariable',
  'RequestBody',
  'RequestHeader',
  'CookieValue',
  'ModelAttribute',
  'MatrixVariable',
])

const TAINT_TAG_NAME_SPRING = 'JAVA_INPUT'

/**
 * Normalize an annotation name to its simple name (strip package prefix and leading @).
 * @param raw
 */
function annotationSimpleName(raw: any): string | undefined {
  if (typeof raw !== 'string') return undefined
  let name = raw.trim()
  if (name.startsWith('@')) name = name.substring(1)
  const parenIdx = name.indexOf('(')
  if (parenIdx !== -1) name = name.substring(0, parenIdx)
  const dotIdx = name.lastIndexOf('.')
  if (dotIdx !== -1) name = name.substring(dotIdx + 1)
  return name || undefined
}

/**
 * Collect annotation simple names attached to a ClassDefinition / FunctionDefinition node.
 * Annotations are materialized either as strings in `_meta.modifiers` / `_meta.annotations`
 * or as AST nodes in `_meta.annotations`.
 * @param node
 */
function collectAnnotationNames(node: any): Set<string> {
  const names = new Set<string>()
  if (!node) return names

  const meta = node._meta
  if (meta) {
    const modifierList = meta.modifiers
    if (Array.isArray(modifierList)) {
      for (const modifier of modifierList) {
        if (typeof modifier === 'string' && modifier.startsWith('@')) {
          const simple = annotationSimpleName(modifier)
          if (simple) names.add(simple)
        }
      }
    }
    const annotationList = meta.annotations
    if (Array.isArray(annotationList)) {
      for (const annotation of annotationList) {
        const simple = extractAnnotationNameFromNode(annotation)
        if (simple) names.add(simple)
      }
    }
  }
  return names
}

/**
 * Extract the annotation simple name from an annotation AST node.
 * Handles VariableDeclaration (id.name), NewExpression (callee.name), and
 * Identifier / MemberAccess forms.
 * @param annotation
 */
function extractAnnotationNameFromNode(annotation: any): string | undefined {
  if (!annotation || typeof annotation !== 'object') return undefined
  if (annotation.type === 'VariableDeclaration') {
    return annotationSimpleName(annotation.id?.name)
  }
  if (annotation.type === 'NewExpression') {
    return annotationSimpleName(annotation.callee?.name || annotation.callee?.property?.name)
  }
  if (annotation.type === 'Identifier') {
    return annotationSimpleName(annotation.name)
  }
  if (annotation.type === 'MemberAccess') {
    return annotationSimpleName(annotation.property?.name)
  }
  if (annotation.type === 'ScopedStatement' && Array.isArray(annotation.body)) {
    for (const stmt of annotation.body) {
      const name = extractAnnotationNameFromNode(stmt)
      if (name) return name
    }
  }
  return undefined
}

/**
 * Determine whether a class node is a Spring controller.
 * @param classNode
 */
function isSpringControllerClass(classNode: any): boolean {
  const annotations = collectAnnotationNames(classNode)
  for (const name of annotations) {
    if (SPRING_CONTROLLER_ANNOTATIONS.has(name)) return true
  }
  return false
}

/**
 * Determine whether a function node is a Spring request handler.
 * @param funcNode
 */
function isSpringHandlerMethod(funcNode: any): boolean {
  const annotations = collectAnnotationNames(funcNode)
  for (const name of annotations) {
    if (SPRING_MAPPING_ANNOTATIONS.has(name)) return true
  }
  return false
}

/**
 * Determine whether a parameter node is annotated with a request-binding annotation.
 * @param paramNode
 */
function isRequestBoundParameter(paramNode: any): boolean {
  const annotations = collectAnnotationNames(paramNode)
  for (const name of annotations) {
    if (SPRING_REQUEST_PARAM_ANNOTATIONS.has(name)) return true
  }
  return false
}

/**
 * Collect the simple names imported from a given package within a compile unit.
 * @param unitNode
 * @param packageName
 */
function collectImportsFromPackage(unitNode: any, packageName: string): Set<string> {
  const imported = new Set<string>()
  const body = unitNode?.body
  if (!Array.isArray(body)) return imported
  for (const stmt of body) {
    if (stmt?.type !== 'VariableDeclaration') continue
    const init = stmt.init
    if (init?.type !== 'ImportExpression') continue
    const from = init.from?.value
    if (typeof from !== 'string') continue
    if (from !== packageName && !from.startsWith(`${packageName}.`)) continue
    const localName = init.local?.name || stmt.id?.name
    if (typeof localName === 'string') imported.add(localName)
  }
  return imported
}

/**
 * Check whether a compile unit imports Spring MVC annotations.
 * @param unitNode
 */
function unitImportsSpringMvc(unitNode: any): boolean {
  const webImports = collectImportsFromPackage(unitNode, SPRING_WEB_ANNOTATION_PACKAGE)
  const stereotypeImports = collectImportsFromPackage(unitNode, SPRING_STEREOTYPE_PACKAGE)
  return webImports.size > 0 || stereotypeImports.size > 0
}

/**
 * Find the enclosing ClassDefinition node for a FunctionDefinition.
 * @param funcNode
 */
function findEnclosingClass(funcNode: any): any {
  let current = funcNode?.parent
  while (current) {
    if (current.type === 'ClassDefinition') return current
    current = current.parent
  }
  return undefined
}

class GeneratedChecker extends JavaTaintAbstractChecker {
  /**
   * Tracks compile units that import Spring MVC so that handler discovery is only
   * attempted for files that actually depend on the framework.
   */
  springCompileUnits: Set<string>

  /**
   * Tracks handler function nodeHashes already registered as entry points to avoid duplicates.
   */
  registeredHandlerHashes: Set<string>

  constructor(resultManager: any, checkerId: any) {
    super(resultManager, "taint_flow_generated")
    this.springCompileUnits = new Set()
    this.registeredHandlerHashes = new Set()
  }

  /**
   * Record Spring MVC compile units and register handler entry points.
   * @param analyzer
   * @param scope
   * @param node
   * @param state
   * @param info
   */
  triggerAtCompileUnit(analyzer: any, scope: any, node: any, state: any, info: any) {
    if (!node || node.type !== 'CompileUnit') return
    if (!unitImportsSpringMvc(node)) return
    const uri = node.uri || node.loc?.sourcefile
    if (typeof uri === 'string') this.springCompileUnits.add(uri)
    this.collectSpringHandlers(analyzer, node)
  }

  /**
   * Walk the compile unit body to find Spring controller classes and register their
   * mapping-annotated methods as entry points.
   * @param analyzer
   * @param unitNode
   */
  collectSpringHandlers(analyzer: any, unitNode: any) {
    const body = unitNode?.body
    if (!Array.isArray(body)) return
    for (const stmt of body) {
      const classNode = stmt?.type === 'ExportStatement' ? stmt.argument : stmt
      if (classNode?.type !== 'ClassDefinition') continue
      if (!isSpringControllerClass(classNode)) continue
      const members = classNode.body
      if (!Array.isArray(members)) continue
      for (const member of members) {
        if (member?.type !== 'FunctionDefinition') continue
        if (!isSpringHandlerMethod(member)) continue
        this.registerHandlerEntryPoint(analyzer, member)
      }
    }
  }

  /**
   * Register a single handler method as an entry point.
   * @param analyzer
   * @param funcNode
   */
  registerHandlerEntryPoint(analyzer: any, funcNode: any) {
    const nodeHash = funcNode?._meta?.nodehash
    if (typeof nodeHash === 'string') {
      if (this.registeredHandlerHashes.has(nodeHash)) return
      this.registeredHandlerHashes.add(nodeHash)
    }

    const fclos = this.resolveFunctionClosure(analyzer, funcNode)
    if (!fclos) return

    const entryPoint = new EntryPoint(constValue.ENGIN_START_FUNCALL)
    entryPoint.scopeVal = fclos.parent
    entryPoint.argValues = []
    entryPoint.entryPointSymVal = fclos
    entryPoint.filePath = funcNode.loc?.sourcefile
    entryPoint.functionName = funcNode.id?.name || funcNode.name
    entryPoint.attribute = 'HTTP'
    entryPoint.parent = fclos.parent
    this.entryPoints.push(entryPoint)
  }

  /**
   * Resolve the function closure for a FunctionDefinition node.
   * Prefer the analyzer symbol table; fall back to the node's own closure reference.
   * @param analyzer
   * @param funcNode
   */
  resolveFunctionClosure(analyzer: any, funcNode: any): any {
    const nodeHash = funcNode?._meta?.nodehash
    if (nodeHash && analyzer?.symbolTable?.get) {
      const resolved = analyzer.symbolTable.get(nodeHash)
      if (resolved && resolved.vtype === 'fclos') return resolved
    }
    if (funcNode?.fclos && funcNode.fclos.vtype === 'fclos') return funcNode.fclos
    return undefined
  }

  /**
   * Mark request-bound parameters of Spring handler methods as taint sources.
   * @param analyzer
   * @param scope
   * @param node
   * @param state
   * @param info
   */
  triggerAtFunctionDefinition(analyzer: any, scope: any, node: any, state: any, info: any) {
    super.triggerAtFunctionDefinition(analyzer, scope, node, state, info)
    const fclos = info?.fclos
    const funcNode = fclos?.ast?.node
    if (!funcNode) return
    const sourceFile = funcNode.loc?.sourcefile
    if (typeof sourceFile === 'string' && this.springCompileUnits.size > 0 && !this.springCompileUnits.has(sourceFile)) {
      return
    }
    if (!isSpringHandlerMethod(funcNode)) return
    const enclosingClass = findEnclosingClass(funcNode)
    if (!enclosingClass || !isSpringControllerClass(enclosingClass)) return

    const parameters = funcNode.parameters
    if (!Array.isArray(parameters)) return
    for (const param of parameters) {
      if (!isRequestBoundParameter(param)) continue
      const paramName = param.id?.name
      if (typeof paramName !== 'string') continue
      this.sourceScope.value.push({
        path: paramName,
        kind: TAINT_TAG_NAME_SPRING,
        scopeFile: sourceFile,
        scopeFunc: funcNode.id?.name || funcNode.name,
        locStart: param.loc?.start?.line,
        locEnd: param.loc?.end?.line,
      })
      this.sourceScope.fillLineValues.push({
        path: paramName,
        kind: TAINT_TAG_NAME_SPRING,
        scopeFile: sourceFile,
        scopeFunc: funcNode.id?.name || funcNode.name,
        locStart: param.loc?.start?.line,
        locEnd: param.loc?.end?.line,
      })
    }
  }
}

module.exports = GeneratedChecker
