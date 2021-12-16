"""
Addon for logging path

Run as follows: mitmproxy -s cookie_logger.py
"""
from mitmproxy import http

class Cookie:
    def request(self, flow: http.HTTPFlow):
        with open("cookie.log", 'a') as file:
            file.write(flow.request.headers["cookie"]+"\n")
        file.close()



addons = [
    Cookie()
]