const { Controller } = require('egg')
const { exec } = require('child_process')

// Intentionally unsafe: static-analysis fixture.
class CommandController extends Controller {
  async run() {
    const command = this.ctx.query.cmd
    exec(command)
    this.ctx.body = 'queued'
  }
}
module.exports = CommandController
