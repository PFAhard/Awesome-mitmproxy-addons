"""
Addon for logging path

Run as follows: mitmproxy -s path_logger.py
"""
import os
from mitmproxy import io, http

class Writter:
    def response(self, flow: http.HTTPFlow) -> None:
        host = flow.request.host
        path = flow.request.path
        file = "responses/"+host+path
        if "?" in file:
            file = file[0:file.find("?")]
        if file.endswith("/"):
            file = file+'index.html'
        if not "." in file[file.rfind("/"):]:
            file = file+".fakext"
        dirs = os.path.dirname(file)
        if not os.path.exists(dirs):
            os.makedirs(dirs)
        with open(file, 'wb') as file:
            file.write(flow.response.content)
    
    def done(self):
        self.f.close()

addons = [Writter()]

    