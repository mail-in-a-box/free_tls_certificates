# For unit testing, we need a simple HTTP server to respond to
# Boulder's SimpleHTTP domain validation calls.

import os.path
import http.server

root_path = "/.well-known/acme-challenge/"

class Handler(http.server.SimpleHTTPRequestHandler):
	def translate_path(self, path):
		if path.startswith(root_path):
			# Strip the well-known prefix so we serve only
			# that directory.
			path = path[len(root_path):]
		fn = super().translate_path(path)
		return fn

	def guess_type(self, path):
		# This content type is required by the ACME spec.
		return "application/jose+json"

server = http.server.HTTPServer(('', 5001), Handler)
server.serve_forever()

