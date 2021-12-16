"""
Addon for logging path

Run as follows: mitmproxy -s path_logger.py
"""
from mitmproxy import http

class Logger:
    def request(self, flow: http.HTTPFlow):
        path = flow.request.path
        host = flow.request.host
        with open("path.log", 'a') as file:
            file.write(host+":"+path+"\n")
        file.close()


addons = [
    Logger()
]