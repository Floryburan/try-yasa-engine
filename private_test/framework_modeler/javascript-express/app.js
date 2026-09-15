const express = require('express')
const { exec } = require('child_process')

// Intentionally unsafe: static-analysis fixture. Do not start this service.
const app = express()
function execute(command) {
  exec(command)
}
function commandHandler(req, res) {
  execute(req.query.cmd)
  res.send('queued')
}
app.get('/command', commandHandler)

// Same registration method name, but this receiver is not an Express app.
const localRegistry = {
  get(name, callback) {
    return name
  },
}
function localHandler(req, res) {
  return 'local'
}
localRegistry.get('/fake', localHandler)

// Not registered on any route.
function unusedHandler(req, res) {
  return 'unused'
}
module.exports = app
