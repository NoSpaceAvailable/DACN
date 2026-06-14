#!/usr/bin/python
# Backend on port 8080 serving the poems directory.

import SimpleHTTPServer
import SocketServer

PORT = 8080
Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
httpd = SocketServer.TCPServer(("", PORT), Handler)
httpd.serve_forever()
