"""
Addon for logging path

Run as follows: mitmproxy -s query_logger.py
"""
from mitmproxy import http

class Query:
    def request(self, flow: http.HTTPFlow):
        with open("query.log", 'a') as file:
            for (k,v) in flow.request.query.items():
                file.write(k+": "+v+"\n")
        file.close()



addons = [
    Query()
]