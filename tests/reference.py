import hashlib, hmac, math, base64

# 深澜门户协议参考实现（用于校验 C# 移植是否正确）
_ALPHABET = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def ordat(msg, idx):
    if len(msg) > idx:
        return ord(msg[idx])
    return 0


def sencode(msg, key):
    l = len(msg)
    pwd = []
    for i in range(0, l, 4):
        pwd.append(
            ordat(msg, i) | ordat(msg, i + 1) << 8 | ordat(msg, i + 2) << 16
            | ordat(msg, i + 3) << 24)
    if key:
        pwd.append(l)
    return pwd


def lencode(msg, key):
    l = len(msg)
    ll = (l - 1) << 2
    if key:
        m = msg[l - 1]
        if m < ll - 3 or m > ll:
            return
        ll = m
    for i in range(0, l):
        msg[i] = chr(msg[i] & 0xff) + chr(msg[i] >> 8 & 0xff) + \
            chr(msg[i] >> 16 & 0xff) + chr(msg[i] >> 24 & 0xff)
    if key:
        return "".join(msg)[0:ll]
    else:
        return "".join(msg)


def xencode(msg, key):
    if msg == "":
        return ""
    pwd = sencode(msg, True)
    pwdk = sencode(key, False)
    if len(pwdk) < 4:
        pwdk = pwdk + [0] * (4 - len(pwdk))
    n = len(pwd) - 1
    z = pwd[n]
    y = pwd[0]
    c = 0x86014019 | 0x183639A0
    m = 0
    e = 0
    p = 0
    q = math.floor(6 + 52 / (n + 1))
    d = 0
    while 0 < q:
        d = d + c & (0x8CE0D9BF | 0x731F2640)
        e = d >> 2 & 3
        p = 0
        while p < n:
            y = pwd[p + 1]
            m = z >> 5 ^ y << 2
            m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
            m = m + (pwdk[(p & 3) ^ e] ^ z)
            pwd[p] = pwd[p] + m & (0xEFB8D130 | 0x10472ECF)
            z = pwd[p]
            p = p + 1
        y = pwd[0]
        m = z >> 5 ^ y << 2
        m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
        m = m + (pwdk[(p & 3) ^ e] ^ z)
        pwd[n] = pwd[n] + m & (0xBB390742 | 0x44C6F8BD)
        z = pwd[n]
        q = q - 1
    return lencode(pwd, False)


def b64(data: bytes) -> str:
    s = base64.b64encode(data).decode()
    return "".join(_ALPHABET[_STD.index(ch)] if ch in _STD else ch for ch in s)


def md5hex(s):
    return hashlib.md5(s.encode()).hexdigest()


def build_info(username, password, ip, acid, enc_ver="srun_bx1"):
    js = '{"username":"%s","password":"%s","ip":"%s","acid":"%s","enc_ver":"%s"}' % (
        username, password, ip, acid, enc_ver)
    return "{SRBX1}" + b64(xencode(js, "srun_bx1").encode("latin1"))


def chksum(username, password, acid, ip, info, n="200", typ="1"):
    s = username + password + acid + ip + n + typ + info
    return hmac.new(b"srun", s.encode(), hashlib.md5).hexdigest()


if __name__ == "__main__":
    u = "20230001"
    p = "{MD5}" + md5hex("Passw0rd!")
    ip = "172.32.18.219"
    acid = "1"
    info = build_info(u, p, ip, acid)
    print("md5:", md5hex("Passw0rd!"))
    print("info:", info)
    print("chk:", chksum(u, p, acid, ip, info))
