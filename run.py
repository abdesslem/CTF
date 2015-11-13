from tornado.wsgi import WSGIContainer
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from womanctf import app

http_server = HTTPServer(WSGIContainer(app))
http_server.listen(5000,'0.0.0.0')
IOLoop.instance().start()
