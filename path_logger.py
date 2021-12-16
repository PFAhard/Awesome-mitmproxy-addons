"""
Basic skeleton of a mitmproxy addon.

Run as follows: mitmproxy -s anatomy.py
"""
from mitmproxy import ctx
import logging

logging.basicConfig(filename='path.log', filemode='w', format='%(message)s')

class Counter:
    def __init__(self):
        self.num = 0

    def request(self, flow):
        path = flow.request.path
        host = flow.request.host
        logging.warning(host+":"+path)



addons = [
    Counter()
]