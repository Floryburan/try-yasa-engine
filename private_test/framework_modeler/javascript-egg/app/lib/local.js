// Local class named Controller is unrelated to egg.Controller.
class Controller {}
class LocalController extends Controller {
  async run() {
    return 'constant'
  }
}
module.exports = LocalController
