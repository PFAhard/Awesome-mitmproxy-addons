"""
Addon for logging path

Run as follows: mitmproxy -s cookie_logger.py
"""
from mitmproxy import http

class Cookie:
    def request(self, flow: http.HTTPFlow):
        with open("cookie.log", 'a') as file:
            try:
                file.write(flow.request.headers["cookie"]+"\n")
            except KeyError:
                pass
        file.close()



addons = [
    Cookie()
]