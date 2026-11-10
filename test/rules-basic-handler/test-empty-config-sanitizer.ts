import * as assert from 'assert'
import { describe, it } from 'mocha'

const SanitizerChecker = require('../../src/checker/sanitizer/sanitizer-checker')
const SanitizerTag = require('../../src/checker/common/value/sanitizer-tag')

function taintedArgument(tags: any[] = []) {
  return { taint: { getTagTracesMap: () => new Map([['PYTHON_INPUT', []]]), getSanitizerTags: () => tags } }
}

describe('Sink configuration sanitizer traversal', () => {
  it('does not traverse a receiver when no configuration sanitizer can match', () => {
    const receiver = { get child() { throw new Error('Unnecessary receiver traversal') } }
    const arg = taintedArgument()
    const result = SanitizerChecker.findTagAndMatchedSanitizer({}, receiver, [arg], null, 'PYTHON_INPUT', true, [])
    assert.strictEqual(result.length, 1)
    assert.strictEqual(result[0].nd, arg)
    assert.deepStrictEqual(result[0].matchedSanitizerTags, [])
  })

  it('still matches flow sanitizers without configuration rules', () => {
    const receiver = { get child() { throw new Error('Unnecessary receiver traversal') } }
    const tag = new SanitizerTag()
    tag.id = 'flow'
    const arg = taintedArgument([tag])
    const result = SanitizerChecker.findTagAndMatchedSanitizer({}, receiver, [arg], null, 'PYTHON_INPUT', true,
      [{ id: 'flow', sanitizerScenario: 'SANITIZER.FILTER_BY_FUNCTIONCALL' }])
    assert.strictEqual(result.length, 1)
    assert.deepStrictEqual(result[0].matchedSanitizerTags, [tag])
  })

  it('continues to search receiver tags when a configuration sanitizer exists', () => {
    const tag = new SanitizerTag()
    tag.id = 'config'
    const receiver = { field: { taint: { getSanitizerTags: () => [tag] } } }
    const arg = taintedArgument()
    const result = SanitizerChecker.findTagAndMatchedSanitizer({}, receiver, [arg], null, 'PYTHON_INPUT', true,
      [{ id: 'config', sanitizerScenario: 'SANITIZER.CONFIG_BY_FUNCTIONCALL' }])
    assert.strictEqual(result.length, 1)
    assert.deepStrictEqual(result[0].matchedSanitizerTags, [tag])
  })
})
