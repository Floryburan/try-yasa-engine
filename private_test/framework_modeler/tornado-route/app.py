import tornado.web


class SearchHandler(tornado.web.RequestHandler):
    def post(self):
        query = self.get_argument("query")
        body = self.request.body
        self.write({"query": query, "body": body})


application = tornado.web.Application([
    (r"/search", SearchHandler),
])

