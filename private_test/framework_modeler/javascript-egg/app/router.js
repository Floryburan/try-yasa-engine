module.exports = app => {
  const { router, controller } = app
  router.get('/command', controller.command.run)
}
