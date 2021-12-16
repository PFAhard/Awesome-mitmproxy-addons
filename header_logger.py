"""
Addon for logging path

Run as follows: mitmproxy -s header_logger.py
"""
from mitmproxy import http


class Header:
    def request(self, flow: http.HTTPFlow):
        with open("headers.log", 'a') as file:
            for k, v in flow.request.headers.items():
                file.write(k+":"+v+"\n")
        file.close()

    def response(self, flow: http.HTTPFlow):
        with open("headers.log", 'a') as file:
            for k, v in flow.response.headers.items():
                file.write(k+":"+v+"\n")
        file.close()



addons = [
    Header()
]