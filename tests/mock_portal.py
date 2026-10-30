"""模拟深澜门户（新版 challenge 协议 + 老版协议），用于端到端验证客户端。

校验点：
1. get_challenge 返回 token
2. 新版：password == {MD5}+HMAC-MD5(key=token, msg=密码)
        chksum  == SHA1(token+u+token+hmd5+token+acid+token+ip+token+n+token+type+token+info)
3. 老版：chksum == HMAC-MD5(u+pwd+acid+ip+n+type+info, key="srun")
4. info 以 {SRBX1} 开头
"""
import hashlib
import hmac
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

PASSWORD = "Passw0rd!"

STATE = {"mode": "normal", "logged_in": False, "token": "", "last_error": "", "requests": []}


def jp(payload):
    return "cb(" + json.dumps(payload, ensure_ascii=False) + ")"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, body, status=200, ctype="application/javascript; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        path = u.path
        STATE["requests"].append(path)

        if path == "/__mode":
            STATE["mode"] = q.get("m", ["normal"])[0]
            STATE["logged_in"] = False
            STATE["last_error"] = ""
            return self._send("ok", ctype="text/plain")

        if path == "/__state":
            return self._send(json.dumps(STATE), ctype="application/json")

        if path == "/generate_204":
            if STATE["logged_in"]:
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if path == "/":
            return self._send("<html><body><script>var ac_id = '1';</script>深澜 校园网认证</body></html>",
                              ctype="text/html; charset=utf-8")

        if path == "/cgi-bin/rad_user_info":
            if STATE["logged_in"]:
                return self._send(jp({"error": "ok", "online_ip": "127.0.0.1",
                                      "user_name": "20230001", "ac_id": "1"}))
            return self._send(jp({"error": "not_online_error", "error_msg": "not online"}))

        if path == "/cgi-bin/get_challenge":
            if STATE["mode"] == "no_challenge":
                return self._send("not found", status=404, ctype="text/plain")
            token = hashlib.md5(os.urandom(16)).hexdigest()
            STATE["token"] = token
            return self._send(jp({"challenge": token, "client_ip": q.get("ip", ["127.0.0.1"])[0],
                                  "error": "ok", "res": "ok", "ecode": 0}))

        if path == "/cgi-bin/srun_portal":
            if STATE["mode"] == "reject_srun":
                return self._send("not found", status=404, ctype="text/plain")
            return self.handle_srun_portal(q)

        if path == "/cgi-bin/do_login":
            return self._send("ok", ctype="text/plain")

        return self._send("not found", status=404, ctype="text/plain")

    def do_POST(self):
        u = urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8", "ignore")
        form = parse_qs(body)
        STATE["requests"].append(u.path + " [POST]")
        if u.path == "/cgi-bin/do_login":
            pwd = form.get("password", [""])[0]
            if pwd == "{MD5}" + hashlib.md5(PASSWORD.encode()).hexdigest():
                STATE["logged_in"] = True
                return self._send("ok", ctype="text/plain")
            return self._send("1", ctype="text/plain")
        return self._send("not found", status=404, ctype="text/plain")

    def handle_srun_portal(self, q):
        g = lambda k, d="": q.get(k, [d])[0]
        action = g("action")
        username = g("username")
        password = g("password")
        acid = g("ac_id")
        ip = g("ip")
        info = g("info")
        n = g("n")
        typ = g("type")
        chksum = g("chksum")
        token = STATE["token"]

        def fail(code, msg):
            STATE["last_error"] = code + ": " + msg
            return self._send(jp({"error": code, "error_msg": msg}))

        if action != "login":
            return fail("login_error", "action 错误")
        if not info.startswith("{SRBX1}"):
            return fail("login_error", "info 格式错误")

        # 新版：token 参与签名
        hmd5 = hmac.new(token.encode(), PASSWORD.encode(), hashlib.md5).hexdigest()
        v2_ok = bool(token) and password == "{MD5}" + hmd5 and \
            hashlib.sha1((token + username + token + hmd5 + token + acid + token + ip +
                          token + n + token + typ + token + info).encode()).hexdigest() == chksum

        # 老版：固定密钥 "srun"
        old_ok = password == "{MD5}" + hashlib.md5(PASSWORD.encode()).hexdigest() and \
            hmac.new(b"srun", (username + password + acid + ip + n + typ + info).encode(),
                     hashlib.md5).hexdigest() == chksum

        if not (v2_ok or old_ok):
            return fail("chksum_error", f"签名校验失败（v2={v2_ok} old={old_ok}）")

        STATE["logged_in"] = True
        return self._send(jp({"error": "ok", "res": "ok", "suc_msg": "login_ok", "ecode": 0,
                              "online_ip": ip, "client_ip": ip}))


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
