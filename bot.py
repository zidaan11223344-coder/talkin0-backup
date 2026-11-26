# Talkin Admin Bot - standalone minimal administration bot
# Based on the Talkin protocol implementation in the user's Kofi Bot.
import os, json, time, uuid, base64, hashlib, socket, ssl, struct, threading, requests, re, errno, select, shutil, subprocess, tempfile
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit

BASE = Path(__file__).resolve().parent
try:
    from dotenv import load_dotenv
    load_dotenv(BASE / ".env", override=False)
except Exception:
    pass
DATA = Path(os.getenv("BOT_DATA_DIR", str(BASE / "admin_data")))
if not DATA.is_absolute():
    DATA = BASE / DATA
DATA.mkdir(parents=True, exist_ok=True)
OWNERS_FILE = DATA / "owners.json"
MANUAL_OWNERS_FILE = DATA / "manual_owners.json"
MASTERS_FILE = DATA / "masters.json"
NO_PHOTO_AUTO_BAN_FILE = DATA / "no_photo_auto_ban.json"
NO_MEMBERSHIP_AUTO_BAN_FILE = DATA / "no_membership_auto_ban.json"
BLACKLIST_FILE = DATA / "blacklist.json"
ROOMS_FILE = DATA / "rooms.json"
INVITE_SETTINGS_FILE = DATA / "invite_settings.json"
BOT_ID = (os.getenv("BOT_ID") or os.getenv("BOT_USERNAME") or "").strip()
BOT_PWD = os.getenv("BOT_PWD") or os.getenv("BOT_PASSWORD") or ""
BOT_MASTER = (os.getenv("BOT_MASTER") or os.getenv("MASTER_USERNAME") or "").strip()
API_BASE_URL = os.getenv("API_BASE_URL", "https://chatp.net/api?").rstrip("?") + "?"
WS_HOSTS = [x.strip() for x in os.getenv("WS_HOSTS", "chatp.net").split(",") if x.strip()]
WS_PATHS = [x.strip() if x.strip().startswith("/") else "/"+x.strip() for x in os.getenv("WS_PATHS", "/server").split(",") if x.strip()] or ["/server"]
DEFAULT_PORT = os.getenv("SOCKET_PORT", "5335").strip()
DEVICE_ID = os.getenv("DEVICE_ID", "talkin-admin-bot")
DEVICE_MODEL = os.getenv("DEVICE_MODEL", "444$samsung-SM-G998B$35")
SDK = os.getenv("SDK", "35")
LANGUAGE = os.getenv("LANGUAGE", "en")
REFERRER_URL = os.getenv("REFERRER_URL", "")
AUTH_VER, AUTH_METHOD = "444", "1"
INVITE_SENDER_NAME = os.getenv("INVITE_SENDER_NAME", "السفير")
INVITE_TEMPLATE = os.getenv("INVITE_MESSAGE_TEMPLATE", "يوجد معجب مخفي في {room}")
GITHUB_REPO_URL = (os.getenv("GITHUB_REPO_URL") or "https://github.com/zidaan11223344-coder/talkin0-backup.git").strip()
GITHUB_TOKEN = (os.getenv("GITHUB_TOKEN") or "").strip()
BACKUP_INTERVAL_SECONDS = max(60, int(os.getenv("BACKUP_INTERVAL_SECONDS", "300")))
# Send private invitations at a conservative pace to avoid flooding the chat service.
INVITE_DELAY = max(0.75, float(os.getenv("INVITE_SEND_INTERVAL_SECONDS", "1.0")))


def norm(s): return str(s or "").strip().lstrip("@").casefold()
def read_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f: return json.load(f)
    except Exception: return default
def write_json(path, value):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)



def _varint(n: int) -> bytes:
    n = int(n)
    if n < 0:
        n &= (1 << 64) - 1
    out = bytearray()
    while n > 0x7F:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n & 0x7F)
    return bytes(out)


def _field_string(num: int, value: str, force: bool = False) -> bytes:
    if value is None:
        value = ""
    raw = str(value).encode("utf-8")
    # APK protobuf classes use presence bits, so forced empty fields are
    # useful for AuthRequest where setters are called even for empty captcha.
    if not raw and not force:
        return b""
    return _varint((num << 3) | 2) + _varint(len(raw)) + raw


def _field_int32(num: int, value: int, force: bool = False) -> bytes:
    value = int(value)
    if value == 0 and not force:
        return b""
    return _varint(num << 3) + _varint(value)


def encode_auth_request(username: str, password: str, captcha_code: str = "", captcha_url: str = "") -> bytes:
    # AuthRequest fields from net.chatp.data.AuthRequest.smali:
    # 1 type, 2 username, 3 password, 4 captchaCode, 5 captchaUrl,
    # 6 sid, 7 sdk, 8 os, 9 ver, 10 clientVer, 11 deviceId,
    # 12 deviceModel, 13 language, 14 method.
    parts = [
        _field_string(1, "login", True),
        _field_string(2, username, True),
        _field_string(3, password, True),
        _field_string(4, captcha_code, True),
        _field_string(5, captcha_url, True),
        _field_string(6, str(uuid.uuid4()), True),
        _field_string(7, SDK, True),
        _field_string(8, "android@" + REFERRER_URL, True),
        _field_string(9, AUTH_VER, True),
        _field_string(10, "2", True),
        _field_string(11, DEVICE_ID, True),
        _field_string(12, DEVICE_MODEL, True),
        _field_string(13, LANGUAGE, True),
        _field_string(14, AUTH_METHOD, True),
    ]
    return b"".join(parts)


def encode_query(action: str, *, type_: str = None, length: str = None,
                 to: str = None, body: str = None, room: str = None,
                 url: str = None, uid: str = None, password: str = None,
                 state: str = None, value: str = None, value1: str = None,
                 int_value: int = None, long_value: int = None,
                 use_bin: int = None, captcha_code: str = None,
                 captcha_url: str = None, id_: str = None,
                 product_id: str = None, order_id: str = None,
                 purchase_time: str = None, purchase_state: str = None,
                 payload: str = None, token: str = None,
                 force_int_value: bool = False) -> bytes:
    # Query fields from net.chatp.data.Query.smali.
    vals = {
        1: action, 2: type_, 3: length, 4: to, 5: body, 6: room,
        7: url, 8: uid, 9: password, 10: state, 11: value, 12: value1,
        16: captcha_code, 17: captcha_url, 18: id_, 19: product_id,
        20: order_id, 21: purchase_time, 22: purchase_state,
        23: payload, 24: token,
    }
    out = bytearray()
    out += _field_string(1, action, True)
    for num in range(2, 25):
        if num in (13, 14, 15):
            continue
        if num in vals and vals[num] is not None:
            out += _field_string(num, vals[num], True)
    if int_value is not None:
        out += _field_int32(13, int_value, force_int_value)
    if long_value is not None:
        out += _varint(14 << 3) + _varint(int(long_value))
    if use_bin is not None:
        out += _field_int32(15, use_bin, True)
    return bytes(out)


def _ws_payload_limit():
    """Outbound Talkin payload limit; keep the service-safe 1008-byte cap."""
    try:
        configured = int(os.getenv("WS_MAX_MESSAGE_BYTES", "1008"))
    except (TypeError, ValueError):
        configured = 1008
    return max(1, min(1008, configured))


def _ws_inbound_payload_limit():
    """Inbound frames can contain full room rosters and are larger than outbound queries."""
    try:
        configured = int(os.getenv("WS_MAX_INBOUND_MESSAGE_BYTES", "262144"))
    except (TypeError, ValueError):
        configured = 262144
    return max(4096, min(1048576, configured))


def read_varint(data: bytes, pos: int):
    value = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        value |= (b & 0x7F) << shift
        if not (b & 0x80):
            return value, pos
        shift += 7
        if shift > 70:
            raise ValueError("invalid protobuf varint")
    raise ValueError("truncated protobuf varint")


def decode_message(data: bytes):
    """Generic protobuf decoder; enough for the APK schemas and nested events."""
    fields = defaultdict(list)
    pos = 0
    while pos < len(data):
        key, pos = read_varint(data, pos)
        num, wire = key >> 3, key & 7
        if num == 0:
            break
        if wire == 0:
            value, pos = read_varint(data, pos)
            fields[num].append(value)
        elif wire == 1:
            if pos + 8 > len(data): raise ValueError("truncated fixed64")
            fields[num].append(data[pos:pos+8]); pos += 8
        elif wire == 2:
            length, pos = read_varint(data, pos)
            if pos + length > len(data): raise ValueError("truncated bytes")
            fields[num].append(data[pos:pos+length]); pos += length
        elif wire == 5:
            if pos + 4 > len(data): raise ValueError("truncated fixed32")
            fields[num].append(data[pos:pos+4]); pos += 4
        else:
            raise ValueError(f"unsupported protobuf wire type {wire}")
    return fields


def as_text(v):
    if isinstance(v, bytes):
        try:
            return v.decode("utf-8")
        except UnicodeDecodeError:
            return ""
    return str(v)


def first_http_url(value):
    """Find the first public HTTP(S) URL in a decoded Talkin payload."""
    if isinstance(value, (str, bytes)):
        text = as_text(value)
        for token in text.replace("\n", " ").split():
            token = token.strip("<>[](){}\"'")
            if token.startswith(("http://", "https://")):
                return token.rstrip(",.;")
        return ""
    if isinstance(value, dict):
        for item in value.values():
            found = first_http_url(item)
            if found:
                return found
    elif isinstance(value, (list, tuple)):
        for item in value:
            found = first_http_url(item)
            if found:
                return found
    return ""


def first_text(fields, num, default=""):
    vals = fields.get(num)
    return as_text(vals[0]) if vals else default


def first_int(fields, num, default=0):
    vals = fields.get(num)
    if not vals: return default
    return int(vals[0]) if isinstance(vals[0], int) else default


def decode_auth_result(data: bytes):
    f = decode_message(data)
    # AuthResult: 1 result, 2 userId, 3 photoUrl, 4 photoVersion,
    # 5 id, 6 message, 7 server, 8 method, 9 enablePing, 10 enableRoomAck.
    return {
        "result": first_text(f, 1),
        "user_id": first_text(f, 2),
        "photo_url": first_text(f, 3),
        "photo_version": first_text(f, 4),
        "id": first_text(f, 5),
        "message": first_text(f, 6),
        "server": first_text(f, 7),
        "method": first_text(f, 8),
        "enable_ping": bool(first_int(f, 9)),
        "enable_room_ack": bool(first_int(f, 10)),
    }


def decode_result_message(data: bytes):
    f = decode_message(data)
    result = {
        "handler_id": first_int(f, 1),
        "type": first_text(f, 2),
        "page": first_int(f, 3),
        "uid": first_text(f, 4),
        "value": first_text(f, 5),
        "int_value": first_int(f, 6),
    }
    # ResultMessage nested protobuf fields:
    # 8 StreamEvent, 9 ChatMessage, 10 RoomEvent, 11 users,
    # 12 rooms, 13 CallInfo, 14 RoomAdmin, 15 LoginInfo, 16 sessions.
    if 8 in f:
        result["stream_event"] = decode_generic(f[8][0])
    if 9 in f:
        result["chat_message"] = decode_generic(f[9][0])
    if 10 in f:
        result["room_event"] = decode_generic(f[10][0])
    if 11 in f:
        result["users"] = [decode_generic(x) for x in f[11]]
    if 12 in f:
        result["rooms"] = [decode_generic(x) for x in f[12]]
    if 13 in f:
        result["call_info"] = decode_generic(f[13][0])
    if 14 in f:
        # Keep RoomAdmin field 10 as raw protobuf bytes so occupants_list can
        # decode each UserItem exactly instead of losing the nested structure.
        ra_fields = decode_message(f[14][0])
        ra = decode_generic(f[14][0])
        if 10 in ra_fields:
            ra[10] = list(ra_fields[10])
        if 11 in ra_fields:
            ra[11] = list(ra_fields[11])
        result["room_admin"] = ra
    if 15 in f:
        result["login_info"] = decode_generic(f[15][0])
    if 16 in f:
        result["sessions"] = [decode_generic(x) for x in f[16]]
    return result


def decode_generic(data: bytes):
    f = decode_message(data)
    out = {}
    for num, vals in f.items():
        converted = []
        for v in vals:
            if isinstance(v, int):
                converted.append(v)
            elif isinstance(v, bytes):
                try:
                    s = v.decode("utf-8")
                    # Nested protobuf objects are also bytes. Prefer text for
                    # fields that look like UTF-8; otherwise expose raw hex.
                    if any(c == "\x00" for c in s):
                        converted.append(v.hex())
                    else:
                        converted.append(s)
                except UnicodeDecodeError:
                    converted.append(v.hex())
        out[num] = converted[0] if len(converted) == 1 else converted
    return out


class RawWebSocket:
    """RFC6455 client closely mirroring the supplied Android Y9/v handshake."""
    MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    def __init__(self, url, headers, timeout=20, debug=False):
        from urllib.parse import urlsplit
        u = urlsplit(url)
        self.scheme = u.scheme
        self.host = u.hostname
        self.port = u.port or (443 if u.scheme == "wss" else 80)
        self.path = u.path or "/"
        if u.query:
            self.path += "?" + u.query
        self.headers = list(headers or [])
        self.timeout = timeout
        self.debug = debug
        self.sock = None
        self._recvbuf = bytearray()
        self.peer_ip = None
        self.permessage_deflate = False
        self._send_lock = threading.Lock()

    def _connect_android_like(self):
        # Android's Y9/s resolves all addresses before creating the socket.
        # We do the same and keep the TLS hostname as chatp.net for SNI/cert check.
        infos = socket.getaddrinfo(self.host, self.port, type=socket.SOCK_STREAM)
        seen = set()
        last = None
        for family, socktype, proto, _canon, sockaddr in infos:
            ip = sockaddr[0]
            if (family, ip, self.port) in seen:
                continue
            seen.add((family, ip, self.port))
            raw = socket.socket(family, socktype, proto)
            raw.settimeout(self.timeout)
            try:
                raw.connect(sockaddr)
                self.peer_ip = ip
                return raw
            except Exception as e:
                last = e
                try: raw.close()
                except Exception: pass
        raise ConnectionError(f"TCP connect failed to {self.host}:{self.port}: {last}")

    def connect(self):
        raw = self._connect_android_like()

        # Android Client obtains the platform default SSLSocketFactory.
        if self.scheme == "wss":
            ctx = ssl.create_default_context()
            self.sock = ctx.wrap_socket(raw, server_hostname=self.host)
        else:
            self.sock = raw
        self.sock.settimeout(self.timeout)

        # Y9/v: SecureRandom -> 16 bytes -> Base64.
        key = base64.b64encode(os.urandom(16)).decode("ascii")

        # Y9/v builds this base order. Newer TalkinChat builds may use a
        # conventional WebSocket stack, so optional compatibility headers are
        # selected by the caller rather than being hard-coded.
        lines = [
            f"GET {self.path} HTTP/1.1",
            f"Host: {self.host}:{self.port}",
            "Connection: Upgrade",
            "Upgrade: websocket",
            "Sec-WebSocket-Version: 13",
            f"Sec-WebSocket-Key: {key}",
        ]
        lines.extend(self.headers)
        request = "\r\n".join(lines) + "\r\n\r\n"

        if self.debug:
            # Header values contain credentials encoded by the APK protocol.
            # Redact username/password header values in diagnostics.
            shown=[]
            for line in lines:
                low=line.lower()
                if low.startswith("username:") or low.startswith("password:"):
                    shown.append(line.split(":",1)[0] + ": <redacted>")
                else:
                    shown.append(line)
            print("[RAW-WS] peer_ip=", self.peer_ip, flush=True)
            print("[RAW-WS] TLS=", self.sock.version(), "cipher=", self.sock.cipher(), flush=True)
            print("[RAW-WS] handshake:\n" + "\\r\\n\n".join(shown) + "\\r\\n\\r\n", flush=True)

        self.sock.sendall(request.encode("utf-8"))

        # Read the complete HTTP response header so a 404 can be diagnosed.
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("server closed during WebSocket handshake")
            buf += chunk
            if len(buf) > 65536:
                raise ConnectionError("oversized WebSocket handshake")

        head, self._prefetch = buf.split(b"\r\n\r\n", 1)
        text = head.decode("iso-8859-1", "replace")
        response_lines = text.split("\r\n")
        status = response_lines[0] if response_lines else ""

        if self.debug:
            print("[RAW-WS] response:", flush=True)
            print(text, flush=True)

        if not (" 101 " in status or status.endswith(" 101")):
            # Include headers/body prefix but never echo credential-bearing request headers.
            body_preview = self._prefetch[:512].decode("utf-8", "replace") if self._prefetch else ""
            detail = status
            if body_preview:
                detail += " | body=" + repr(body_preview)
            raise ConnectionError("WebSocket handshake rejected: " + detail)

        h = {}
        for line in response_lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                h[k.strip().lower()] = v.strip()
        ext = h.get("sec-websocket-extensions", "")
        self.permessage_deflate = "permessage-deflate" in ext.lower()
        if self.debug and ext:
            print("[RAW-WS] negotiated extensions:", ext, flush=True)
        expected = base64.b64encode(hashlib.sha1((key + self.MAGIC).encode("ascii")).digest()).decode("ascii")
        if h.get("sec-websocket-accept") != expected:
            raise ConnectionError("invalid Sec-WebSocket-Accept")
        self._recvbuf = bytearray(self._prefetch)

    def _recv_exact(self, n):
        try:
            socket_timeout = self.sock.gettimeout()
        except Exception:
            socket_timeout = None
        wait_timeout = socket_timeout if socket_timeout is not None else getattr(self, "timeout", 20)
        deadline = time.monotonic() + max(0.1, float(wait_timeout or 20))
        while len(self._recvbuf) < n:
            try:
                chunk = self.sock.recv(max(4096, n-len(self._recvbuf)))
            except InterruptedError:
                continue
            except BlockingIOError as exc:
                if exc.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                    raise
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise socket.timeout("timed out waiting for WebSocket data") from exc
                # EAGAIN is a normal transient result on a non-blocking socket.
                # Wait for readability instead of tearing down the whole bot.
                try:
                    select.select([self.sock], [], [], remaining)
                except InterruptedError:
                    pass
                continue
            if not chunk:
                raise ConnectionError("socket closed")
            self._recvbuf.extend(chunk)
        out = bytes(self._recvbuf[:n]); del self._recvbuf[:n]
        return out

    def send_binary(self, payload):
        payload = bytes(payload)
        max_bytes = _ws_payload_limit()
        if len(payload) > max_bytes:
            print(f"[WS_DROP_OVERSIZE] تم تجاهل إرسال حزمة WebSocket بحجم {len(payload)} بايت لتجاوزها الحد الآمن ({max_bytes} بايت) لمنع فصل الخادم برمز 1009.", flush=True)
            return False
        mask = os.urandom(4)
        n = len(payload)
        if n < 126:
            hdr = bytes([0x82, 0x80 | n])
        elif n <= 0xffff:
            hdr = bytes([0x82, 0x80 | 126]) + struct.pack('!H', n)
        else:
            hdr = bytes([0x82, 0x80 | 127]) + struct.pack('!Q', n)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        with self._send_lock:
            self.sock.sendall(hdr + mask + masked)
        return True

    def send_control(self, opcode, payload=b''):
        payload = bytes(payload); mask = os.urandom(4)
        if len(payload) > 125: raise ValueError('control frame too large')
        hdr = bytes([0x80 | opcode, 0x80 | len(payload)])
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        with self._send_lock:
            self.sock.sendall(hdr + mask + masked)

    def recv(self):
        b1, b2 = self._recv_exact(2)
        rsv1 = bool(b1 & 0x40)
        opcode = b1 & 0x0f; masked = bool(b2 & 0x80); n = b2 & 0x7f
        if n == 126: n = struct.unpack('!H', self._recv_exact(2))[0]
        elif n == 127: n = struct.unpack('!Q', self._recv_exact(8))[0]
        mask = self._recv_exact(4) if masked else b''
        # The 1008-byte restriction is for client-to-server queries only.
        # Talkin can return full member lists (the supplied log shows 9150 bytes).
        # Drop unusually large frames in chunks so they cannot allocate unbounded memory.
        max_bytes = _ws_inbound_payload_limit()
        if opcode in (0x1, 0x2, 0x0) and n > max_bytes:
            remaining = n
            while remaining:
                take = min(remaining, 8192)
                self._recv_exact(take)
                remaining -= take
            return ("oversize", {"size": n, "limit": max_bytes})

        data = self._recv_exact(n)
        if masked: data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        if rsv1 and self.permessage_deflate and opcode in (0x1, 0x2, 0x0):
            import zlib
            try:
                inflater = zlib.decompressobj(-zlib.MAX_WBITS)
                data = inflater.decompress(data + b"\x00\x00\xff\xff", max_bytes + 1)
            except zlib.error:
                pass
        if opcode in (0x1, 0x2, 0x0) and len(data) > max_bytes:
            return ("oversize", {"size": len(data), "limit": max_bytes})
        if opcode == 0x8:
            code = None; reason = ''
            if len(data) >= 2:
                try:
                    code = struct.unpack('!H', data[:2])[0]
                    reason = data[2:].decode('utf-8', 'replace')
                except Exception:
                    pass
            # A peer-initiated close must be acknowledged before reconnecting.
            try:
                self.send_control(0x8, data[:125])
            except Exception:
                pass
            return ('close', {'code': code, 'reason': reason, 'raw': data})
        if opcode == 0x9:
            self.send_control(0xA, data); return ('ping', data)
        if opcode == 0xA: return ('pong', data)
        if opcode == 0x1: return ('text', data.decode('utf-8', 'replace'))
        if opcode == 0x2: return ('binary', data)
        return ('other', data)

    def close(self):
        try:
            if self.sock: self.send_control(0x8, b'')
        except Exception: pass
        try:
            if self.sock: self.sock.close()
        except Exception: pass
        self.sock = None

class GitHubBackup:
    """Non-blocking Git mirror for the bot project and its admin_data directory.

    Uses GITHUB_TOKEN from the host environment for HTTPS GitHub authentication.
    The token is passed to git through a temporary process environment only.
    """
    EXCLUDED_DIRS = {
        ".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache",
        ".talkin_backup_work", ".enzonic-trash", ".local", ".cache",
        ".npm", ".cargo", ".rustup", ".tox", ".nox", "node_modules",
        "site-packages", "__pypackages__",
    }
    EXCLUDED_FILES = {".env", ".env.local", ".env.production"}

    def __init__(self, base_dir, repo_url, log):
        self.base = Path(base_dir).resolve()
        self.repo_url = str(repo_url or "").strip()
        self.log = log
        self.lock = threading.RLock()
        self.thread = None
        self.stop_event = threading.Event()
        self.workdir = Path(tempfile.gettempdir()) / ("talkin0_backup_" + hashlib.sha1(str(self.base).encode()).hexdigest()[:10])
        self.repo_dir = self.workdir / "repo"
        self.ready = False
        self.last_signature = None

    def _git_env(self):
        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GCM_INTERACTIVE"] = "never"
        # Fail promptly on stalled GitHub connections instead of leaving the
        # background worker apparently silent for several minutes.
        env["GIT_CONFIG_COUNT"] = "3"
        env["GIT_CONFIG_KEY_0"] = "http.lowSpeedLimit"
        env["GIT_CONFIG_VALUE_0"] = "1000"
        env["GIT_CONFIG_KEY_1"] = "http.lowSpeedTime"
        env["GIT_CONFIG_VALUE_1"] = "30"
        env["GIT_CONFIG_KEY_2"] = "http.https://github.com/.extraheader"
        if GITHUB_TOKEN:
            # Fine-grained PAT: Contents read/write on the target repository.
            # The credential is not written to the remote URL or committed files.
            auth = base64.b64encode(("x-access-token:" + GITHUB_TOKEN).encode("utf-8")).decode("ascii")
            env["GIT_CONFIG_VALUE_2"] = "AUTHORIZATION: basic " + auth
        else:
            env.pop("GIT_CONFIG_KEY_2", None)
            env.pop("GIT_CONFIG_VALUE_2", None)
            env["GIT_CONFIG_COUNT"] = "2"
        return env

    def _git(self, *args, check=True):
        safe_args = ["<remote>" if str(a).startswith("https://") else str(a) for a in args]
        self.log("[BACKUP] git:", " ".join(safe_args[:4]))
        result = subprocess.run(["git", "-C", str(self.repo_dir), *args],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, timeout=75, env=self._git_env())
        if check and result.returncode:
            raise RuntimeError((result.stderr or result.stdout or "git command failed").strip()[-1200:])
        return result

    def _ignore(self, directory, names):
        ignored = set()
        for name in names:
            if name in self.EXCLUDED_DIRS or name in self.EXCLUDED_FILES:
                ignored.add(name)
            elif name.endswith((".pyc", ".pyo", ".log", ".tmp")):
                ignored.add(name)
        return ignored

    def _signature(self):
        parts = []
        for root, dirs, files in os.walk(self.base):
            dirs[:] = sorted(d for d in dirs if d not in self.EXCLUDED_DIRS)
            for name in sorted(files):
                if name in self.EXCLUDED_FILES or name.endswith((".pyc", ".pyo", ".log", ".tmp")):
                    continue
                path = Path(root) / name
                try:
                    st = path.stat()
                    parts.append((str(path.relative_to(self.base)), st.st_size, st.st_mtime_ns))
                except OSError:
                    continue
        return hashlib.sha1(repr(parts).encode()).hexdigest()

    def _prepare(self):
        if not self.repo_url:
            raise RuntimeError("رابط مستودع GitHub غير مضبوط.")
        if not GITHUB_TOKEN:
            raise RuntimeError("أضف متغير GITHUB_TOKEN في إعدادات الاستضافة.")
        if shutil.which("git") is None:
            raise RuntimeError("Git غير مثبت على الاستضافة.")
        if not self.repo_url.startswith("https://github.com/"):
            raise RuntimeError("استخدم رابط HTTPS لمستودع GitHub، وليس SSH.")
        self.log("[BACKUP] preflight passed; git=", shutil.which("git"),
                 "token_present=", bool(GITHUB_TOKEN), "repo=", self.repo_url)
        self.workdir.mkdir(parents=True, exist_ok=True)
        if not (self.repo_dir / ".git").exists():
            if self.repo_dir.exists():
                shutil.rmtree(self.repo_dir, ignore_errors=True)
            self.log("[BACKUP] cloning repository; this may take a short while")
            try:
                result = subprocess.run(["git", "clone", "--progress", self.repo_url, str(self.repo_dir)],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        text=True, timeout=75, env=self._git_env())
            except subprocess.TimeoutExpired:
                raise RuntimeError("انتهت مهلة الاتصال أثناء استنساخ المستودع من GitHub (75 ثانية). تحقق من اتصال الاستضافة." )
            if result.returncode:
                raise RuntimeError((result.stderr or result.stdout or "git clone failed").strip()[-1200:])
            self.log("[BACKUP] repository clone completed")
        else:
            self.log("[BACKUP] existing local backup repository found")
        self._git("config", "user.name", "Talkin Backup")
        self._git("config", "user.email", "talkin-backup@users.noreply.github.com")
        self._git("checkout", "-B", "main", check=False)
        self.ready = True

    def _replace_snapshot(self):
        # Merge the live project into the existing clone.  Do NOT wipe files
        # already present in GitHub: the repository may contain permanent
        # assets/configuration that are not part of the currently running
        # process directory.  Existing files with the same relative path are
        # updated; repository-only files are preserved.
        try:
            shutil.copytree(self.base, self.repo_dir, dirs_exist_ok=True,
                            ignore=self._ignore, symlinks=False)
        except shutil.Error as exc:
            # copytree may collect hundreds/thousands of failures. Never send
            # that entire list to the master; report a compact diagnosis.
            failures = exc.args[0] if exc.args and isinstance(exc.args[0], list) else []
            first_reason = failures[0][2] if failures and len(failures[0]) > 2 else str(exc)
            raise RuntimeError(
                f"تعذر تجهيز ملفات النسخة الاحتياطية ({len(failures)} أخطاء نسخ). "
                f"أول خطأ: {first_reason}. تحقق من مساحة القرص واستثناء مجلدات النظام."
            ) from None
        # Never include local Git metadata or credentials from the source tree.
        for name in self.EXCLUDED_FILES:
            (self.repo_dir / name).unlink(missing_ok=True)

    def sync_once(self):
        with self.lock:
            if not self.ready:
                self._prepare()
            self.log("[BACKUP] preparing project snapshot")
            self._replace_snapshot()
            self.log("[BACKUP] snapshot copied; staging files")
            self._git("add", "-A", "-f")
            status = self._git("status", "--porcelain").stdout.strip()
            changed = bool(status)
            if changed:
                self._git("commit", "-m", "Talkin automatic backup")
            # Always retry push: a previous network failure may have left a
            # local commit waiting even when the working tree is now clean.
            self.log("[BACKUP] uploading snapshot to GitHub")
            push = self._git("push", "-u", "origin", "HEAD:main", check=False)
            if push.returncode:
                # If the repository already has a main branch, integrate it
                # before retrying instead of silently overwriting remote data.
                pull = self._git("pull", "--rebase", "origin", "main", check=False)
                if pull.returncode:
                    raise RuntimeError((push.stderr or pull.stderr or "git push failed").strip()[-1200:])
                self._git("push", "-u", "origin", "HEAD:main")
            self.last_signature = self._signature()
            return changed

    def start(self, on_initial_done=None):
        with self.lock:
            if self.thread and self.thread.is_alive():
                return False
            self.stop_event.clear()
            def worker():
                try:
                    self.log("[BACKUP] starting first full project backup")
                    changed = self.sync_once()
                    self.log("[BACKUP] initial backup pushed" if changed else "[BACKUP] repository already up to date")
                    if on_initial_done:
                        detail = "تم تحديث المستودع بنجاح" if changed else "المستودع محدث بالفعل"
                        try:
                            notified = on_initial_done(True, detail)
                            if notified is False:
                                self.log("[BACKUP] success reply was not delivered")
                        except Exception as callback_exc:
                            self.log("[BACKUP] success notification failed:", repr(callback_exc))
                except Exception as exc:
                    error_text = str(exc).strip() or exc.__class__.__name__
                    # Keep the chat notification short and readable; full
                    # diagnostics remain in the hosting log.
                    self.log("[BACKUP] initial backup failed:", repr(error_text[:1200]))
                    if on_initial_done:
                        try:
                            notified = on_initial_done(False, "فشل تحديث المستودع: " + error_text[:700])
                            if notified is False:
                                self.log("[BACKUP] failure reply was not delivered")
                        except Exception as callback_exc:
                            self.log("[BACKUP] failure notification failed:", repr(callback_exc))
                    return
                # Continuous background sync starts only after the first
                # master-triggered backup succeeds.
                while not self.stop_event.wait(BACKUP_INTERVAL_SECONDS):
                    try:
                        signature = self._signature()
                        if signature != self.last_signature:
                            time.sleep(3)  # debounce active JSON writes
                            if self.sync_once():
                                self.log("[BACKUP] background changes synchronized")
                    except Exception as exc:
                        self.log("[BACKUP] background sync failed:", repr(exc))
            self.thread = threading.Thread(target=worker, name="talkin-github-backup", daemon=True)
            self.thread.start()
            return True


class TalkinAdminBot:
    def __init__(self):
        self.http = requests.Session()
        self.ws = None
        self.auth = None
        self.port = DEFAULT_PORT
        self.captcha_id = "0"
        self.photo_version = "0"
        self.roster_version = "0"
        self.rooms = set(read_json(ROOMS_FILE, []))
        first = os.getenv("GROUP_TO_JOIN", "").strip()
        self.rooms.update(x.strip() for x in os.getenv("ROOMS", "").split(",") if x.strip())
        if first: self.rooms.add(first)
        self.owners = read_json(OWNERS_FILE, {})
        if not isinstance(self.owners, dict): self.owners = {}
        # Only manually-added owners are auto-promoted on join / demoted on leave.
        self.manual_owners = read_json(MANUAL_OWNERS_FILE, {})
        if not isinstance(self.manual_owners, dict): self.manual_owners = {}
        self.masters = read_json(MASTERS_FILE, {})
        if not isinstance(self.masters, dict): self.masters = {}
        self.no_photo_auto_ban = bool(read_json(NO_PHOTO_AUTO_BAN_FILE, False))
        # Per-room switch: As@on / As@off. State survives process restarts.
        self.no_membership_auto_ban = read_json(NO_MEMBERSHIP_AUTO_BAN_FILE, {})
        if not isinstance(self.no_membership_auto_ban, dict):
            self.no_membership_auto_ban = {}
        self.blacklist = read_json(BLACKLIST_FILE, {})
        if not isinstance(self.blacklist, dict): self.blacklist = {}
        # Invite text and target room are persisted independently of .env.
        invite_settings = read_json(INVITE_SETTINGS_FILE, {})
        if not isinstance(invite_settings, dict):
            invite_settings = {}
        self.invite_template = str(invite_settings.get("message") or INVITE_TEMPLATE)
        self.invite_room = str(invite_settings.get("room") or "").strip()
        self.github_backup = GitHubBackup(BASE, GITHUB_REPO_URL, self.log)
        self.pending_owner_imports = {}
        self.owner_import_timer = None
        self.pending_named_commands = {}
        self.pending_admin_actions = {}
        self.pending_admin_timers = {}
        self.pending_admin_lock = threading.RLock()
        self._heartbeat_stop = None
        self._heartbeat_thread = None
        self.lock = threading.RLock()
        self.invite_jobs = {}
        # Each invite roster request carries its own room/category/attempt
        # metadata. This prevents an out-of-order room_admin reply from being
        # consumed by another room's invite operation.
        self.invite_request_timers = {}
        self.pending_lists = {}
        # One bulk-invite worker per room.  A repeated command must not start a
        # second list collector while the first one is still sending DMs.
        self.invite_lock = threading.RLock()

    def log(self, *a): print(time.strftime("%H:%M:%S"), *a, flush=True)
    def send_query(self, payload):
        if not self.ws:
            self.log("[WS] send skipped: socket is not connected")
            return False
        return self.ws.send_binary(payload) is True
    def send_room_text(self, room, text):
        """Send a normal Talkin room text message (same packet shape as Kofi)."""
        room_name = str(room or "").strip()
        if not room_name:
            self.log("[REPLY] room send skipped: empty room")
            return False
        message = str(text or "")
        if not message:
            self.log("[REPLY] room send skipped: empty message", room_name)
            return False
        try:
            # Talkin requires type_='text' for room_message. Without field 2,
            # the server may accept the packet but not publish it in the room.
            packet = encode_query("room_message", type_="text", body=message, room=room_name)
            if len(packet) > _ws_payload_limit():
                self.log("[REPLY] room message exceeds packet limit", room_name, len(packet))
                return False
            sent = self.send_query(packet)
            if sent is False:
                self.log("[REPLY] room send rejected", room_name)
                return False
            self.log("[REPLY] room message sent", "room=", room_name, "bytes=", len(packet))
            return True
        except Exception as exc:
            self.log("[REPLY] room send failed", "room=", room_name, "error=", repr(exc))
            return False
    def send_private_text(self, user, text):
        """Send a private reply reliably, splitting text before the WS hard limit."""
        username = str(user or "").strip().lstrip("@")
        # Canonicalize every reply to the exact configured master handle,
        # including list pages that were passed the sender's display casing.
        if username and BOT_MASTER and norm(username) == norm(BOT_MASTER):
            username = str(BOT_MASTER).strip().lstrip("@")
        if not username:
            self.log("[REPLY] private send skipped: empty recipient")
            return False

        message = str(text or "")
        limit = max(160, _ws_payload_limit() - 48)
        chunks = []
        current = ""
        for char in message:
            candidate = current + char
            packet_size = len(encode_query("chat_message", type_="text", to=username, body=candidate))
            if packet_size > limit and current:
                chunks.append(current)
                current = char
            else:
                current = candidate
        if current or not chunks:
            chunks.append(current)

        for index, chunk in enumerate(chunks, 1):
            packet = encode_query("chat_message", type_="text", to=username, body=chunk)
            if len(packet) > _ws_payload_limit():
                self.log("[REPLY] private chunk exceeds packet limit", username, len(packet))
                return False
            try:
                sent = self.send_query(packet)
                if sent is False:
                    self.log("[REPLY] private send rejected", username, "part=", index)
                    return False
                self.log("[REPLY] private sent", "to=", username, "part=", f"{index}/{len(chunks)}", "bytes=", len(packet))
            except Exception as exc:
                self.log("[REPLY] private send failed", "to=", username, repr(exc))
                return False
            if index < len(chunks):
                time.sleep(0.12)
        return True

    def authenticate(self):
        r = self.http.post(API_BASE_URL + "auth_new", data=encode_auth_request(BOT_ID, BOT_PWD),
            headers={"Content-Type":"application/octet-stream", "User-Agent":"Talkinchat/1.0 (Android 12; net.chatp)"}, timeout=20)
        r.raise_for_status(); self.auth = decode_auth_result(r.content)
        if self.auth.get("result", "").lower() not in ("ok", "success", "true", "1"):
            raise RuntimeError("Authentication rejected: " + str(self.auth.get("message") or self.auth.get("result")))
        self.port = self.auth.get("server") if str(self.auth.get("server", "")).isdigit() else DEFAULT_PORT
        self.captcha_id = self.auth.get("id") or os.getenv("CAPTCHA_ID", "0")
        self.photo_version = self.auth.get("photo_version") or "0"
        self.log("[AUTH] authenticated; server=", self.port)

    def ws_headers(self):
        raw = f"{self.captcha_id}@{DEVICE_ID}@{DEVICE_MODEL}@android@{LANGUAGE}@{self.photo_version}@{self.roster_version}"
        return ["b: " + base64.b64encode(raw.encode()).decode()]

    def join_configured_rooms(self):
        write_json(ROOMS_FILE, sorted(self.rooms))
        for room in sorted(self.rooms):
            self.send_query(encode_query("room_join", room=room, int_value=0, force_int_value=True))
            self.log("[ROOM] join requested:", room)
            time.sleep(0.35)

    def change_role(self, room, username, role):
        if role not in ("owner", "admin", "member", "outcast"): raise ValueError("unsupported role")
        return self.send_query(encode_query("room_admin", type_="change_role", room=room,
                                            to=username.lstrip("@"), value=role))

    def add_owner(self, username):
        name = str(username or "").strip().lstrip("@")
        key = norm(name)
        if not key: return False
        self.owners[key] = name
        self.manual_owners[key] = name
        write_json(OWNERS_FILE, self.owners)
        write_json(MANUAL_OWNERS_FILE, self.manual_owners)
        return True

    def remove_owner(self, username):
        key = norm(username)
        if key not in self.owners: return False
        del self.owners[key]
        self.manual_owners.pop(key, None)
        write_json(OWNERS_FILE, self.owners)
        write_json(MANUAL_OWNERS_FILE, self.manual_owners)
        return True

    def add_master(self, username):
        name = str(username or "").strip().lstrip("@")
        key = norm(name)
        if not key: return False
        self.masters[key] = name
        write_json(MASTERS_FILE, self.masters)
        return True

    @staticmethod
    def joined_user_has_no_photo(event):
        """Return True only when a photo field is explicitly present and empty."""
        aliases = ("photo_url", "photoUrl", "avatar", "avatar_url", "avatarUrl", "image_url")
        for key in aliases:
            if key in event:
                value = event.get(key)
                if isinstance(value, list): value = value[0] if value else ""
                return not bool(str(value or "").strip())
        # Talkin UserItem/AuthResult convention uses field 3 for photo URL.
        # Missing field means unknown, not an empty-photo account.
        for key in (3, "3"):
            if key in event:
                value = event.get(key)
                if isinstance(value, list): value = value[0] if value else ""
                text = str(value or "").strip()
                return not text or text.casefold() in ("none", "null", "default", "no_photo")
        return False

    @staticmethod
    def joined_user_has_no_membership(event):
        """True only when Talkin explicitly reports a no-membership role.

        Missing role data is treated as unknown and never triggers a ban.
        """
        value = ""
        for key in ("role", "affiliation", "muc_affiliation", "rank", "value", 8, "8", 31, "31"):
            if key in event and event.get(key) is not None:
                raw = event.get(key)
                if isinstance(raw, list):
                    raw = raw[0] if raw else ""
                value = str(raw or "").strip().casefold().replace(" ", "_")
                if value:
                    break
        if not value:
            return False
        aliases = {
            "none", "no_role", "norole", "without_role", "unranked",
            "guest", "visitor", "unknown", "0", "null", "unset",
            "لا_يوجد", "بدون_عضوية", "بدون_رتبة"
        }
        return value in aliases

    def no_membership_protection_enabled(self, room):
        return bool(self.no_membership_auto_ban.get(norm(room), False))

    def set_no_membership_protection(self, room, enabled):
        key = norm(room)
        if not key:
            return False
        self.no_membership_auto_ban[key] = bool(enabled)
        write_json(NO_MEMBERSHIP_AUTO_BAN_FILE, self.no_membership_auto_ban)
        return True

    def add_blacklist(self, username):
        name = str(username or "").strip().lstrip("@")
        key = norm(name)
        if not key: return False
        self.blacklist[key] = name
        write_json(BLACKLIST_FILE, self.blacklist)
        return True

    def remove_blacklist(self, username):
        name = str(username or "").strip().lstrip("@").strip().strip(".,;:!?\"'`،؛")
        key = norm(name)
        if not key:
            return False
        # Repair old entries whose keys may have included an @ or whitespace.
        found = [k for k, value in self.blacklist.items()
                 if norm(k) == key or norm(value) == key]
        if not found:
            return False
        for old_key in found:
            self.blacklist.pop(old_key, None)
        write_json(BLACKLIST_FILE, self.blacklist)
        self.log("[BLACKLIST] removed:", name, "remaining=", len(self.blacklist))
        return True

    def send_room_list(self, room, title, names, empty="📭 لا توجد أسماء."):
        """Send Kofi-style numbered room lists in WebSocket-safe pages."""
        room = str(room or "").strip()
        clean, seen = [], set()
        for value in names or []:
            name = str(value or "").strip().lstrip("@")
            key = norm(name)
            if name and key not in seen and key != norm(BOT_ID):
                seen.add(key)
                clean.append(name)
        clean.sort(key=str.casefold)
        if not clean:
            self.send_room_text(room, f"{title} (0)\n{empty}")
            return 0

        max_bytes = _ws_payload_limit()
        header = f"{title} ({len(clean)}):"
        pages, current = [], [header]
        for index, name in enumerate(clean, 1):
            line = f"{index}. @{name}"
            probe = "\n".join(current + [line]) + "\n📄 القائمة 9999/9999"
            if len(encode_query("room_message", type_="text", body=probe, room=room)) > max_bytes and len(current) > 1:
                pages.append("\n".join(current))
                current = [header, line]
            else:
                current.append(line)
        if len(current) > 1:
            pages.append("\n".join(current))

        total = len(pages)
        for page_no, page in enumerate(pages, 1):
            message = f"{page}\n📄 القائمة {page_no}/{total}"
            if len(encode_query("room_message", type_="text", body=message, room=room)) > max_bytes:
                self.log("[LIST] skipped one over-limit room list page", room, page_no)
                continue
            self.send_room_text(room, message)
            if page_no < total:
                time.sleep(0.25)
        return len(clean)

    def send_private_list(self, username, title, names, empty="📭 لا توجد أسماء."):
        """Send a numbered private list in safe, sequential messages."""
        clean, seen = [], set()
        for value in names or []:
            name = str(value or "").strip().lstrip("@")
            key = norm(name)
            if name and key not in seen and key != norm(BOT_ID):
                seen.add(key)
                clean.append(name)
        clean.sort(key=str.casefold)
        if not clean:
            self.send_private_text(username, f"{title} (0)\n{empty}")
            return 0
        max_bytes = _ws_payload_limit()
        header = f"{title} ({len(clean)}):"
        pages, current = [], [header]
        for index, name in enumerate(clean, 1):
            line = f"{index}. @{name}"
            probe = "\n".join(current + [line]) + "\n📄 القائمة 9999/9999"
            if len(encode_query("chat_message", type_="text", to=username, body=probe)) > max_bytes and len(current) > 1:
                pages.append("\n".join(current))
                current = [header, line]
            else:
                current.append(line)
        if len(current) > 1:
            pages.append("\n".join(current))
        total = len(pages)
        for page_no, page in enumerate(pages, 1):
            message = f"{page}\n📄 القائمة {page_no}/{total}"
            if len(encode_query("chat_message", type_="text", to=username, body=message)) > max_bytes:
                self.log("[LIST] skipped one over-limit private list page", username, page_no)
                continue
            self.send_private_text(username, message)
            if page_no < total:
                time.sleep(0.25)
        return len(clean)

    def _request_admin_role(self, room, username, role, requester, private=False):
        room = str(room or "").strip()
        name = str(username or "").strip().lstrip("@")
        if role not in ("owner", "admin", "member"):
            self.reply(room, requester, "❌ رتبة الإدارة غير معروفة. استخدم: اونر أو اشراف أو عضو.", private)
            return False
        if not room:
            self.reply(room, requester, "⚠️ لا توجد غرفة محددة. نفّذ أمر الرتبة داخل الغرفة المطلوبة، مثل: o@username أو a@username أو m@username.", private)
            return False
        if not name:
            self.reply(room, requester, "⚠️ اكتب اسم المستخدم بعد الأمر.", private)
            return False

        key = (norm(room), norm(name), role)
        timer = threading.Timer(15.0, self._admin_confirmation_timeout, args=(key,))
        timer.daemon = True
        with self.pending_admin_lock:
            if key in self.pending_admin_actions:
                self.reply(room, requester, f"⏳ طلب {role} للمستخدم @{name} قيد التنفيذ بالفعل.", private)
                return False
            self.pending_admin_actions[key] = {
                "room": room, "target": name, "role": role,
                "requester": requester, "private": bool(private),
                "created_at": time.time(),
            }
            self.pending_admin_timers[key] = timer
        try:
            # Register the pending action before sending; Talkin may emit the
            # role_changed event immediately after accepting the packet.
            self.change_role(room, name, role)
        except Exception as exc:
            with self.pending_admin_lock:
                self.pending_admin_actions.pop(key, None)
                stale_timer = self.pending_admin_timers.pop(key, None)
            if stale_timer:
                stale_timer.cancel()
            self.log("[ADMIN] role request failed:", room, name, role, repr(exc))
            self.reply(room, requester, f"❌ لم أتمكن من إرسال أمر {self._role_label(role)} للمستخدم @{name}. تحقق من اتصال البوت وصلاحياته.", private)
            return False

        timer.start()
        # Do not tell the master that the server is still processing. A request
        # packet is not a role change; the only success reply is emitted by the
        # matching native role_changed event below.
        self.log("[ADMIN] role request sent; waiting silently for native confirmation:",
                 room, name, role)
        return True

    @staticmethod
    def _role_label(role):
        return {"owner": "الأونر", "admin": "الإشراف", "member": "العضو"}.get(role, "الرتبة")

    def _admin_confirmation_timeout(self, key):
        with self.pending_admin_lock:
            pending = self.pending_admin_actions.pop(key, None)
            self.pending_admin_timers.pop(key, None)
        if not pending:
            return
        msg = (f"⚠️ لم يصلني حدث تأكيد تغيير رتبة @{pending['target']} إلى "
               f"{self._role_label(pending['role'])} في غرفة {pending['room']}. "
               "لا أستطيع تأكيد النجاح من إرسال الطلب وحده. إذا ظهرت الرتبة متغيرة فعلاً، "
               "فهذا يعني أن Talkin لم يرسل حدث التأكيد لهذا الاتصال.")
        try:
            self.reply(pending["room"], pending["requester"], msg, bool(pending.get("private")))
        except Exception as exc:
            self.log("[ADMIN] timeout notification failed:", repr(exc))

    def _handle_admin_permission_error(self, room, body):
        """Turn Talkin's native 'bot must be owner/master' rejection into a clear reply."""
        text = str(body or "").casefold()
        if not room or "master only" not in text:
            return False
        if not any(token in text for token in (
            "needs bot master", "bot master / owner", "needs owner",
            "master or owner", "bot must be owner"
        )):
            return False
        matched = []
        with self.pending_admin_lock:
            for key, pending in list(self.pending_admin_actions.items()):
                if norm(pending.get("room")) == norm(room):
                    matched.append((key, self.pending_admin_actions.pop(key, None)))
                    timer = self.pending_admin_timers.pop(key, None)
                    if timer:
                        timer.cancel()
        for key, pending in matched:
            if not pending:
                continue
            self.reply(
                room, pending.get("requester") or BOT_MASTER,
                ("❌ رفض Talkin تغيير الرتبة: حساب البوت نفسه ليس أونر/مالكاً في هذه الغرفة. "
                 "ارفع حساب البوت إلى أونر أولاً، ثم أعد الأمر. "
                 "صلاحية الماستر في إعدادات البوت لا تمنح البوت صلاحية أونر داخل الغرفة."),
                bool(pending.get("private")),
            )
            self.log("[ADMIN] Talkin permission rejection:", room,
                     pending.get("target"), pending.get("role"))
        return bool(matched)

    def _confirm_admin_role_event(self, room, event):
        """Confirm only from Talkin's native role_changed target (field 17)."""
        room = str(room or "").strip()

        def value(*keys):
            for key in keys:
                item = event.get(key, event.get(str(key), ""))
                if isinstance(item, list):
                    item = item[0] if item else ""
                if item is not None and str(item).strip():
                    return str(item).strip()
            return ""

        # In Talkin RoomEvent, field 17 is the affected account, while 22 may
        # be the actor who issued the change. Never treat field 22 as target.
        role_values = [value(31, "new_role", "changed_role"),
                       value(8, "role", "user_role"), value("value")]
        changed_role = next(
            (item.casefold().replace(" ", "_") for item in role_values if item), ""
        )
        changed_role = {
            "o": "owner", "a": "admin", "m": "member",
            "moderator": "admin", "moderators": "admin",
            "room_owner": "owner", "creator": "owner",
            "عضو": "member", "مشرف": "admin", "اونر": "owner", "أونر": "owner",
            "banned": "outcast", "ban": "outcast", "kicked": "outcast",
        }.get(changed_role, changed_role)
        # Different Talkin builds put the affected account in field 17 or 22.
        # Only an exact match against a pending target can confirm an action,
        # so including both does not let an unrelated actor confirm it.
        candidates = [value(key) for key in ("target", "to", "username", "user", 17, 22)]
        candidates = [candidate for candidate in dict.fromkeys(candidates) if candidate]
        if not room or changed_role not in ("owner", "admin", "member") or not candidates:
            return False

        found_key = None
        pending = None
        with self.pending_admin_lock:
            for key, item in self.pending_admin_actions.items():
                if norm(item.get("room")) != norm(room) or item.get("role") != changed_role:
                    continue
                if any(norm(candidate) == norm(item.get("target")) for candidate in candidates):
                    found_key, pending = key, item
                    break
            if found_key is not None:
                self.pending_admin_actions.pop(found_key, None)
                timer = self.pending_admin_timers.pop(found_key, None)
                if timer:
                    timer.cancel()
        if not pending:
            return False

        labels = {
            "owner": f"✅ تم رفع @{pending['target']} إلى أونر بنجاح.",
            "admin": f"✅ تم رفع @{pending['target']} إلى الإشراف بنجاح.",
            "member": f"✅ تم إرجاع @{pending['target']} إلى رتبة عضو بنجاح.",
        }
        try:
            self.reply(room, pending["requester"], labels[changed_role], bool(pending.get("private")))
        except Exception as exc:
            self.log("[ADMIN] confirmation reply failed:", repr(exc))
        self.log("[ADMIN] server confirmed:", room, pending["target"], changed_role)
        return True

    def request_owner_import(self, room, requester=None, private=False):
        room = str(room or "").strip()
        if not room:
            return False
        if self.pending_owner_imports:
            self.reply(room, requester or BOT_MASTER,
                       "⏳ يوجد طلب تحميل أونرات قيد التنفيذ؛ انتظر حتى ينتهي.", private)
            return False
        request_id = uuid.uuid4().hex[:20]
        self.pending_owner_imports = {
            "room": room, "request_id": request_id, "created_at": time.time(),
            "requester": requester or BOT_MASTER, "private": bool(private),
        }
        try:
            self.send_query(encode_query("room_admin", type_="owners_list", room=room,
                                         to=BOT_ID, value="none", id_=request_id))
        except Exception as exc:
            self.pending_owner_imports = {}
            self.log("[OWNER-IMPORT] request send failed:", repr(exc))
            self.reply(room, requester or BOT_MASTER,
                       "❌ فشل إرسال طلب تحميل الأونرات إلى Talkin. تحقق من اتصال البوت.", private)
            return False
        self.log("[OWNER-IMPORT] requested owners_list:", room, "request_id=", request_id)
        self.reply(room, requester or BOT_MASTER,
                   "⏳ تم إرسال طلب تحميل الأونرات. سأعرض العدد فور وصول رد السيرفر.", private)
        timer = threading.Timer(20.0, self._owner_import_timeout, args=(request_id,))
        timer.daemon = True
        self.owner_import_timer = timer
        timer.start()
        return True

    def _owner_import_timeout(self, request_id):
        pending = self.pending_owner_imports
        if not pending or pending.get("request_id") != request_id:
            return
        room = pending.get("room", "")
        requester = pending.get("requester") or BOT_MASTER
        private = bool(pending.get("private"))
        self.pending_owner_imports = {}
        self.owner_import_timer = None
        self.log("[OWNER-IMPORT] timeout waiting for Talkin response:", room)
        try:
            self.reply(room, requester,
                       "❌ لم يصل رد قائمة الأونرات من السيرفر خلال 20 ثانية. لم يتم تحميل أي أسماء. تأكد أن البوت أونر في الغرفة ثم أعد المحاولة.",
                       private)
        except Exception as exc:
            self.log("[OWNER-IMPORT] timeout reply failed:", repr(exc))

    def master_ok(self, sender):
        key = norm(sender)
        return bool(key and ((BOT_MASTER and key == norm(BOT_MASTER)) or key in self.masters))

    def command(self, room, sender, body, private=False):
        msg = str(body or "").strip()
        low = msg.casefold()
        if not self.master_ok(sender):
            self.log("[COMMAND] ignored: sender is not configured master", repr(sender),
                     "private=", private, "room=", repr(room))
            return
        self.log("[COMMAND] accepted", "sender=", sender, "private=", private,
                 "room=", repr(room), "text=", msg[:120])

        if low.startswith(("ماستر@", "ماستر @")):
            name = msg.split("@", 1)[1].strip().split()[0] if "@" in msg else ""
            if not name:
                self.reply(room, sender, "⚠️ الصيغة: ماستر@اسم_المستخدم", private)
            elif norm(name) in self.masters or (BOT_MASTER and norm(name) == norm(BOT_MASTER)):
                self.reply(room, sender, f"ℹ️ @{name} لديه صلاحية ماستر بالفعل.", private)
            elif self.add_master(name):
                self.reply(room, sender, f"✅ تمت إضافة @{name} كـماستر متحكم بالبوت.", private)
            else:
                self.reply(room, sender, "❌ تعذرت إضافة الماستر.", private)
            return

        if low in ("نسخ احتياطي", "نسخ_احتياطي", "backup"):
            if not GITHUB_REPO_URL:
                self.reply(room, sender,
                           "⚠️ لم يتم ضبط رابط المستودع. أضف GITHUB_REPO_URL إلى .env ثم أعد تشغيل البوت.",
                           private)
                return
            started = self.github_backup.start(
                lambda ok, detail: self.reply(room, sender,
                    ("✅ " if ok else "❌ ") + detail +
                    ("\n🔄 المزامنة التلقائية مستمرة كل " + str(BACKUP_INTERVAL_SECONDS // 60) + " دقيقة." if ok else
                     "\nراجع سجل الاستضافة عند [BACKUP] لمعرفة السبب، وتأكد من GITHUB_TOKEN وصلاحية Contents: Read and write."),
                    private)
            )
            if started:
                self.reply(room, sender,
                           "⏳ بدأ النسخ الاحتياطي الكامل في الخلفية. لن يتوقف البوت عن استقبال الأوامر، وستبدأ المزامنة المستمرة بعد نجاح أول رفع.",
                           private)
            else:
                self.reply(room, sender, "⏳ النسخ الاحتياطي والمزامنة يعملان بالفعل بالخلفية.", private)
            return

        if low in ("اختبار الرد", "تجربة الرد", "فحص الرد", "ping"):
            self.reply(room, sender,
                       "✅ الرد يعمل. وصلتني رسالتك من الماستر، وقناة الرد الخاصة جاهزة.",
                       private)
            return

        # Complete a Kofi-style two-step rank command: command first, username next.
        pending_name = self.pending_named_commands.get(norm(sender))
        if pending_name:
            age = time.time() - float(pending_name.get("created_at", 0) or 0)
            if age > 180:
                self.pending_named_commands.pop(norm(sender), None)
            elif msg and not self._looks_like_admin_input(msg):
                self.pending_named_commands.pop(norm(sender), None)
                self._request_admin_role(
                    pending_name.get("room") or room, msg.split()[0],
                    pending_name.get("role"), sender,
                    bool(pending_name.get("private")),
                )
                return
            elif msg and self._looks_like_admin_input(msg):
                # A new command cancels the previous prompt; never apply a stale rank command later.
                self.pending_named_commands.pop(norm(sender), None)

        if low.startswith(("اضف اونر", "أضف اونر", "add owner")):
            prefix = next(x for x in ("اضف اونر", "أضف اونر", "add owner") if low.startswith(x.casefold()))
            name = msg[len(prefix):].strip().lstrip("@")
            if not name:
                self.reply(room, sender, "⚠️ اكتب اسم المستخدم. مثال: اضف اونر @username", private)
            elif norm(name) in self.owners:
                key = norm(name)
                if key not in self.manual_owners:
                    self.manual_owners[key] = self.owners[key]
                    write_json(MANUAL_OWNERS_FILE, self.manual_owners)
                    self.reply(room, sender, f"✅ @{name} موجود مسبقًا وتم تسجيله كأونر مضاف يدويًا؛ سيُعاد عند الدخول ويُسحب عند المغادرة.", private)
                else:
                    self.reply(room, sender, f"ℹ️ @{name} موجود بالفعل كأونر مضاف يدويًا.", private)
            elif self.add_owner(name):
                self.reply(room, sender, f"✅ تم حفظ @{name} ضمن قائمة الأونرات الدائمة.", private)
            else:
                self.reply(room, sender, f"❌ تعذر حفظ @{name} في قائمة الأونرات.", private)
            return

        if low.startswith(("احذف اونر", "حذف اونر", "ازالة اونر", "إزالة اونر", "remove owner")):
            prefixes = ("احذف اونر", "حذف اونر", "ازالة اونر", "إزالة اونر", "remove owner")
            prefix = next(x for x in prefixes if low.startswith(x.casefold()))
            name = msg[len(prefix):].strip().lstrip("@")
            ok = self.remove_owner(name) if name else False
            self.reply(room, sender, (f"✅ تم حذف @{name} من قائمة الأونرات المحفوظة." if ok else ("⚠️ اكتب اسم المستخدم." if not name else f"⚠️ @{name} غير موجود في قائمة الأونرات.")), private)
            return

        if low == "as@on":
            if private or not room:
                self.reply(room, sender, "⚠️ نفّذ As@on داخل الغرفة التي تريد حمايتها.", private)
                return
            self.set_no_membership_protection(room, True)
            self.reply(room, sender,
                       f"✅ تم تفعيل الحظر التلقائي للحسابات التي يصرّح السيرفر بأنها بلا عضوية.\n🏠 الغرفة: {room}\n🛡️ الأعضاء والمشرفون والأونرات مستثنون.", private)
            return
        if low == "as@off":
            if private or not room:
                self.reply(room, sender, "⚠️ نفّذ As@off داخل الغرفة التي تريد إيقاف الحماية فيها.", private)
                return
            self.set_no_membership_protection(room, False)
            self.reply(room, sender, f"⛔ تم إيقاف حظر الحسابات بلا عضوية.\n🏠 الغرفة: {room}", private)
            return

        if low in ("حظر بدون صورة", "تفعيل حظر بدون صورة", "حظر الحسابات بدون صورة", "ap@on"):
            self.no_photo_auto_ban = True
            write_json(NO_PHOTO_AUTO_BAN_FILE, True)
            self.reply(room, sender, "✅ تم تفعيل الحظر التلقائي للحسابات التي يدخل أصحابها بلا صورة (عندما تصل معلومة الصورة صراحةً من السيرفر).", private)
            return
        if low in ("ايقاف حظر بدون صورة", "إيقاف حظر بدون صورة", "تعطيل حظر بدون صورة",
                   "ايقافap@off", "إيقافap@off", "ap@off"):
            self.no_photo_auto_ban = False
            write_json(NO_PHOTO_AUTO_BAN_FILE, False)
            self.reply(room, sender, "✅ تم إيقاف الحظر التلقائي للحسابات بدون صورة.", private)
            return

        blacklist_add_prefixes = ("بلاك@", "blacklist@", "اضف بلاك@", "أضف بلاك@",
                                  "بلاك @", "اضف بلاك ", "أضف بلاك ")
        blacklist_add_prefix = next((x for x in blacklist_add_prefixes if low.startswith(x.casefold())), None)
        if blacklist_add_prefix is not None:
            raw_name = msg[len(blacklist_add_prefix):].strip()
            name = raw_name.lstrip("@").split()[0] if raw_name else ""
            if not name:
                self.reply(room, sender, "⚠️ اكتب اسم المستخدم. الصيغة: بلاك@اسم_المستخدم", private)
            elif norm(name) in self.blacklist:
                self.reply(room, sender, f"ℹ️ @{name} موجود بالفعل في قائمة البلاك؛ لم أكرر إضافته.", private)
            elif self.add_blacklist(name):
                sent = False
                if room:
                    try:
                        self.change_role(room, name, "outcast")
                        sent = True
                    except Exception as exc:
                        self.log("[BLACKLIST] immediate ban request failed:", repr(exc))
                self.reply(room, sender,
                           f"⛔ تم إضافة @{name} إلى قائمة البلاك الدائمة."
                           + (" وأُرسل طلب حظره في هذه الغرفة." if room and sent else ""), private)
            else:
                self.reply(room, sender, f"❌ تعذرت إضافة @{name} إلى قائمة البلاك.", private)
            return

        remove_prefixes = ("حذف البلاك", "حذف بلاك", "ازالة البلاك", "إزالة البلاك",
                           "ازالة بلاك", "إزالة بلاك", "-بلاك", "unblacklist")
        remove_prefix = next((x for x in remove_prefixes if low.startswith(x.casefold())), None)
        if remove_prefix:
            tail = msg[len(remove_prefix):].strip()
            name = tail.split("@", 1)[1].strip() if "@" in tail else tail.strip().lstrip("@")
            name = name.split()[0].strip() if name else ""
            if not name:
                self.reply(room, sender, "⚠️ اكتب اسم المستخدم. مثال: حذف بلاك @username", private)
                return
            if self.remove_blacklist(name):
                self.reply(room, sender, f"✅ تم حذف البلاك عن @{name} بنجاح.", private)
            else:
                self.reply(room, sender, f"⚠️ غير موجود في قائمة البلاك: @{name}.", private)
            return

        if low in ("قائمة البلاك", "البلاك ليست", "blacklist"):
            names = sorted(self.blacklist.values(), key=str.casefold)
            if room and not private:
                self.send_room_list(room, "⛔ قائمة البلاك", names, "📭 قائمة البلاك فارغة.")
            else:
                self.send_private_list(sender, "⛔ قائمة البلاك", names, "📭 قائمة البلاك فارغة.")
            self.reply(room, sender, f"✅ تم عرض قائمة البلاك. العدد: {len(names)}", private)
            return

        if low in ("l@o", "تحميل الاونرات", "تحميل الأونرات", "تحميل اونرات", "تحميل أونرات"):
            if not room:
                self.reply(room, sender, "⚠️ نفّذ أمر تحميل الأونرات داخل الغرفة المطلوب جلب قائمتها.", private)
            else:
                self.request_owner_import(room, requester=sender, private=private)
            return

        if low in ("قائمة الاونرات", "قائمة الأونرات", "owners"):
            names = sorted(self.owners.values(), key=str.casefold)
            if room:
                self.send_room_list(room, "👑 قائمة الأونرات المحفوظة", names, "📭 لا توجد أسماء محفوظة حالياً.")
                self.reply(room, sender, f"✅ تم عرض قائمة الأونرات المحفوظة. العدد: {len(names)}", private)
            else:
                self.send_private_list(sender, "👑 قائمة الأونرات المحفوظة", names, "📭 القائمة فارغة.")
                self.reply(room, sender, f"✅ تم عرض قائمة الأونرات المحفوظة. العدد: {len(names)}", private)
            return

        # Kofi-compatible role aliases: o@ / a@ / m@ and named two-step commands.
        role_direct_prefixes = (
            ("owner", ("o@", "owner ", "اونر@", "أونر@", "اونر ", "أونر ", "رفع اونر@", "رفع أونر@", "رفع اونر ", "رفع أونر ")),
            ("admin", ("a@", "admin ", "ادمن ", "أدمن ", "إدمن ", "ادمن@", "أدمن@", "إدمن@", "اشراف@", "إشراف@", "مشرف@", "اشراف ", "إشراف ", "مشرف ", "رفع اشراف@", "رفع إشراف@", "رفع مشرف@", "رفع اشراف ", "رفع إشراف ", "رفع مشرف ", "رفع ادمن ", "رفع أدمن ")),
            ("member", ("m@", "member ", "عضو@", "عضو ", "رفع عضو@", "رفع عضو ", "انزال اونر@", "إنزال اونر@", "انزال اونر ", "إنزال اونر ", "تنزيل اونر@", "تنزيل اونر ", "انزال اشراف@", "إنزال اشراف@", "انزال اشراف ", "إنزال اشراف ", "سحب اونر@", "سحب اونر ", "سحب اشراف@", "سحب اشراف ")),
        )
        for role, prefixes in role_direct_prefixes:
            prefix = next((x for x in prefixes if low.startswith(x.casefold())), None)
            if prefix is not None:
                target = msg[len(prefix):].strip().lstrip("@")
                if not target:
                    self._prompt_rank_name(room, sender, role, private)
                else:
                    self._request_admin_role(room, target.split()[0], role, sender, private)
                return

        named_role = {
            "اونر": "owner", "أونر": "owner", "owner": "owner",
            "اشراف": "admin", "إشراف": "admin", "مشرف": "admin", "ادمن": "admin", "أدمن": "admin", "admin": "admin",
            "عضو": "member", "member": "member",
            "رفع اونر": "owner", "رفع أونر": "owner",
            "انزال اونر": "member", "إنزال اونر": "member", "تنزيل اونر": "member", "سحب اونر": "member",
            "انزال اشراف": "member", "إنزال اشراف": "member", "سحب اشراف": "member",
            "رفع اشراف": "admin", "رفع إشراف": "admin", "رفع مشرف": "admin",
            "رفع ادمن": "admin", "رفع أدمن": "admin", "رفع عضو": "member",
        }.get(low)
        if named_role:
            self._prompt_rank_name(room, sender, named_role, private)
            return

        # Master can make the bot join a room from private chat or a room.
        join_prefix = next((x for x in ("ادخل الغرفة", "دخول", "ادخل")
                            if low == x or low.startswith(x + " ") or low.startswith(x + "@")), None)
        if join_prefix is not None:
            target = msg[len(join_prefix):].strip()
            if target.startswith("@"):
                target = target[1:].strip()
            target = target.strip().strip("،,;؛")
            if not target:
                self.reply(room, sender, "⚠️ اكتب اسم الغرفة. مثال: دخول اسم_الغرفة", private)
                return
            try:
                self.rooms.add(target)
                write_json(ROOMS_FILE, sorted(self.rooms))
                self.send_query(encode_query("room_join", room=target, int_value=0, force_int_value=True))
                self.log("[ROOM] master join requested:", target, "via_private=", private)
                self.reply(room, sender, f"📨 تم إرسال طلب دخول البوت إلى غرفة: {target}\n✅ حُفظت الغرفة لإعادة دخولها بعد إعادة التشغيل.", private)
            except Exception as exc:
                self.log("[ROOM] master join failed:", target, repr(exc))
                self.reply(room, sender, f"❌ تعذر إرسال طلب دخول الغرفة {target}: {exc}", private)
            return

        # Persistent invitation customization. These settings override the
        # .env invitation template and survive every restart.
        if low.startswith("imvmsg@"):
            new_message = msg.split("@", 1)[1].strip()
            if not new_message:
                self.reply(room, sender, "⚠️ اكتب نص الدعوة بعد imvmsg@.", private)
                return
            # Keep the room placeholder fixed even when the master types only
            # the invitation sentence after invmsg@.
            if "{room}" not in new_message:
                new_message = new_message.rstrip() + " {room}"
            self.invite_template = new_message
            write_json(INVITE_SETTINGS_FILE, {
                "message": self.invite_template,
                "room": self.invite_room,
            })
            self.reply(room, sender,
                       "✅ تم حفظ رسالة الدعوة الجديدة بشكل دائم. ستبقى بعد إعادة تشغيل البوت، ولن يعود إلى نص المتغيرات في .env.",
                       private)
            self.log("[INV] custom invitation message saved")
            return

        if low.startswith("imvroom@"):
            target_room = msg.split("@", 1)[1].strip()
            if not target_room:
                self.reply(room, sender, "⚠️ اكتب اسم الغرفة بعد imvroom@.", private)
                return
            self.invite_room = target_room
            write_json(INVITE_SETTINGS_FILE, {
                "message": self.invite_template,
                "room": self.invite_room,
            })
            self.reply(room, sender,
                       f"✅ تم حفظ غرفة الدعوات: {target_room}\n📨 أمر (دعوات) سينفذ الدعوات في هذه الغرفة حتى بعد إعادة التشغيل. تأكد أن البوت موجود فيها.",
                       private)
            self.log("[INV] invitation room saved:", target_room)
            return

        if low in ("دعوات", "دعوة", "inv", "invite"):
            target_room = self.invite_room or ("" if private else str(room or "").strip())
            if not target_room:
                self.reply(room, sender,
                           "⚠️ حدّد غرفة الدعوات أولاً بالأمر: imvroom@اسم الغرفة",
                           private)
                return
            self.start_invites(target_room)
            return

        if low in ("اوامر", "الأوامر", "مساعدة", "help", "commands"):
            help_text = ("🤖 أوامر الإدارة المتاحة للماستر\n"
                         "━━━━━━━━━━━━\n"
                         "⛔ بلاك@اسم — إضافة إلى البلاك\n"
                         "🖼️ حظر بدون صورة — تفعيل الحظر التلقائي للحسابات بلا صورة\n"
                         "🖼️ إيقاف حظر بدون صورة — إيقافه\n"
                         "🖼️ ap@on / ايقافap@off — تفعيل/إيقاف الحظر التلقائي بدون صورة\n"
                         "🚫 As@on / As@off — تفعيل/إيقاف حظر الحسابات بلا عضوية (لكل غرفة)\n"
                         "✅ حذف البلاك @اسم — حذف من البلاك\n"
                         "📋 قائمة البلاك — عرض المحظورين\n"
                         "👑 l@o أو تحميل الاونرات — جلب الأونرات وحفظهم وعرضهم\n"
                         "👑 قائمة الاونرات — عرض الأونرات المحفوظة\n"
                         "➕ اضف اونر @اسم / احذف اونر @اسم (يدوي: يُعاد عند الدخول ويُسحب عند المغادرة)\n"
                         "🧭 ماستر@اسم_المستخدم — إضافة ماستر متحكم دائم\n"
                         "👑 o@اسم — رفع أونر\n"
                         "🛡️ a@اسم — رفع إشراف\n"
                         "👤 m@اسم — إرجاع إلى عضو\n"
                         "🏠 دخول اسم_الغرفة — إدخال البوت إلى غرفة\n"
                         "✉️ imvmsg@نص الدعوة — تغيير نص الدعوة وحفظه دائماً\n"
                         "🏠 imvroom@اسم الغرفة — تحديد غرفة الدعوات وحفظها\n"
                         "📨 دعوات — تنفيذ الدعوات في الغرفة المحددة\n"
                         "💾 نسخ احتياطي — رفع ملفات البوت وadmin_data ثم تشغيل المزامنة التلقائية")
            self.reply(room, sender, help_text, private)
            return

        # The command handler is reached for every text event in a room.
        # Ordinary conversation from the master is not a bot command and must
        # never trigger an unsolicited reply.
        if self._looks_like_admin_input(msg) or low.startswith((
            "قائمة", "owners", "blacklist", "دعوة", "دعوات", "دخول", "ادخل",
            "اوامر", "الأوامر", "مساعدة", "help", "اختبار", "تجربة"
        )):
            self.reply(room, sender,
                       "🤔 لم أتعرف على صيغة الأمر. اكتب (اوامر) لعرض الأوامر الصحيحة.",
                       private)
            self.log("[COMMAND] unknown admin-like input:", repr(msg),
                     "private=", private, "room=", room)
        else:
            self.log("[COMMAND] ordinary text ignored (not a command):",
                     repr(msg[:80]), "private=", private, "room=", room)

    def _prompt_rank_name(self, room, sender, role, private=False):
        if not room:
            self.reply(room, sender, "⚠️ ابدأ أمر الرتبة من داخل الغرفة المطلوبة.", private)
            return
        self.pending_named_commands[norm(sender)] = {
            "room": str(room), "role": role, "private": bool(private), "created_at": time.time(),
        }
        prompts = {
            "owner": "👑 ارسل اسم المستخدم الآن لرفعه أونر في هذه الغرفة.",
            "admin": "🛡️ ارسل اسم المستخدم الآن لرفعه إشراف في هذه الغرفة.",
            "member": "👤 ارسل اسم المستخدم الآن لإرجاعه عضو في هذه الغرفة.",
        }
        self.reply(room, sender, prompts[role], private)

    def _looks_like_admin_input(self, msg):
        low = str(msg or "").strip().casefold()
        prefixes = ("بلاك@", "blacklist@", "حذف البلاك", "حذف بلاك", "اضف اونر", "أضف اونر",
                    "احذف اونر", "حذف اونر", "o@", "a@", "m@", "اونر", "أونر",
                    "اشراف", "إشراف", "مشرف", "ادمن", "عضو", "دخول", "ادخل",
                    "تحميل الاونرات", "تحميل الأونرات", "قائمة الاونرات", "قائمة الأونرات", "دعوات",
                    "حظر بدون صورة", "تفعيل حظر بدون صورة", "حظر الحسابات بدون صورة",
                    "ايقاف حظر بدون صورة", "إيقاف حظر بدون صورة", "تعطيل حظر بدون صورة",
                    "ap@on", "ايقافap@off", "إيقافap@off", "ap@off", "as@on", "as@off",
                    "imvmsg@", "imvroom@", "نسخ احتياطي", "نسخ_احتياطي", "backup")
        return low.startswith(prefixes)

    def reply(self, room, sender, text, private):
        """Reply strictly in the channel where the command was received.

        Do not silently turn a room reply into a private message when the room
        name is missing. That used to hide bad inbound room routing and made
        the master receive room-command results in PM.
        """
        try:
            if private:
                recipient = str(sender or "").strip().lstrip("@")
                if not recipient:
                    self.log("[REPLY] private send skipped: no recipient; sender=", repr(sender))
                    return False
                ok = self.send_private_text(recipient, text)
                if not ok:
                    self.log("[REPLY] private reply was not delivered", "recipient=", recipient)
                else:
                    self.log("[REPLY] private reply sent", "recipient=", recipient)
                return ok

            room_name = str(room or "").strip()
            if not room_name:
                self.log("[REPLY] ROOM CONTEXT MISSING; refusing to send a room command reply privately",
                         "sender=", repr(sender), "text=", str(text or "")[:100])
                return False
            ok = self.send_room_text(room_name, text)
            if ok is False:
                self.log("[REPLY] room reply was not delivered", "room=", room_name)
            else:
                self.log("[REPLY] room reply sent", "room=", room_name)
            return ok
        except Exception as exc:
            self.log("[REPLY] failed", "private=", private, "room=", repr(room),
                     "sender=", repr(sender), "error=", repr(exc))
            return False

    def send_private_invite(self, username, room):
        """Send one invitation through the normal private-message pipeline.

        The old bulk path wrote a raw chat_message packet directly, which
        bypassed the same validation/retry behavior used by the previous bot.
        Keep the invitation formatting in one place and delegate transport to
        send_private_text().
        """
        username = str(username or "").strip().lstrip("@")
        room = str(room or "").strip()
        if not username or not room or norm(username) == norm(BOT_ID):
            return False
        text = self.invite_template
        if "{room}" not in text:
            text = text.rstrip() + " {room}"
        text = text.format(sender=INVITE_SENDER_NAME, room=room, username=username)
        return self.send_private_text(username, text)

    def start_invites(self, room):
        key = norm(room)
        with self.invite_lock:
            if key in self.invite_jobs:
                self.send_room_text(room, "⏳ عملية الدعوات جارية بالفعل."); return
            self.invite_jobs[key] = {
                "room": room,
                "queue": ["owners_list", "admins_list", "members_list"],
                "users": {}, "bot_owner": False,
                "started_at": time.time(), "sending": False,
            }
        self.send_room_text(room, "⏳ بدأت العملية: أجمع الأونرات والمشرفين والأعضاء، ثم أرسل الدعوات الخاصة.")
        try:
            self.request_next_invite_list(key)
        except Exception as exc:
            with self.invite_lock:
                self.invite_jobs.pop(key, None)
            self.log("[INV] start failed:", repr(exc))
            self.send_room_text(room, "❌ تعذر بدء جمع قائمة الأعضاء. تحقق من صلاحية البوت واتصاله ثم أعد الأمر.")

    def request_next_invite_list(self, key):
        job = self.invite_jobs.get(key)
        if not job: return
        if not job["queue"]:
            if not job["bot_owner"]:
                self.send_room_text(job["room"], "⚠️ لم يؤكد Talkin أن البوت أونر في الغرفة؛ لم تُرسل الدعوات.")
                self.invite_jobs.pop(key, None); return
            names = [v for k,v in job["users"].items() if k != norm(BOT_ID)]
            threading.Thread(target=self.finish_invites, args=(key,names), daemon=True).start(); return
        category = job["queue"].pop(0)
        req = uuid.uuid4().hex[:18]
        self.pending_lists[req] = {
            "job_key": key, "category": category, "room": str(job["room"]),
            "attempt": "app", "request_id": req, "requested_at": time.time(),
        }
        try:
            # Match the app flow first; older gateways are retried with the
            # legacy BOT_ID target by _invite_list_timeout().
            sent = self.send_query(encode_query(
                "room_admin", type_=category, room=job["room"],
                to="username", value="none", id_=req,
            ))
            if sent is False:
                raise RuntimeError("roster request was not sent")
            timer = threading.Timer(10.0, self._invite_list_timeout, args=(req,))
            timer.daemon = True
            self.invite_request_timers[req] = timer
            timer.start()
            self.log("[INV] requested", category, "for", job["room"], "target=app", "id=", req)
        except Exception as exc:
            self.pending_lists.pop(req, None)
            self.log("[INV] roster request failed:", category, job["room"], repr(exc))
            self._abort_invite_job(key, "❌ تعذر طلب قائمة أعضاء الغرفة؛ لم تُرسل الدعوات.")

    def _abort_invite_job(self, key, message):
        """Cancel one invite operation and all of its pending roster timers."""
        job = self.invite_jobs.pop(key, None)
        if not job:
            return False
        for req, meta in list(self.pending_lists.items()):
            if isinstance(meta, dict) and meta.get("job_key") == key:
                timer = self.invite_request_timers.pop(req, None)
                if timer:
                    timer.cancel()
                self.pending_lists.pop(req, None)
        try:
            self.send_room_text(str(job.get("room") or ""), message)
        except Exception as exc:
            self.log("[INV] abort notice failed:", repr(exc))
        return True

    def _invite_list_timeout(self, request_id):
        """Retry an app-style roster request once, then abort safely."""
        meta = self.pending_lists.get(request_id)
        if not isinstance(meta, dict) or meta.get("request_id") != request_id:
            return False
        key = meta.get("job_key")
        job = self.invite_jobs.get(key)
        if not job:
            self.pending_lists.pop(request_id, None)
            return False
        if meta.get("attempt") == "app":
            self.pending_lists.pop(request_id, None)
            self.invite_request_timers.pop(request_id, None)
            retry_id = uuid.uuid4().hex[:18]
            retry = dict(meta, attempt="legacy", request_id=retry_id, requested_at=time.time())
            self.pending_lists[retry_id] = retry
            try:
                sent = self.send_query(encode_query(
                    "room_admin", type_=retry["category"], room=retry["room"],
                    to=BOT_ID, value="none", id_=retry_id,
                ))
                if sent is False:
                    raise RuntimeError("legacy roster request was not sent")
                timer = threading.Timer(10.0, self._invite_list_timeout, args=(retry_id,))
                timer.daemon = True
                self.invite_request_timers[retry_id] = timer
                timer.start()
                self.log("[INV] retrying roster request", retry["category"],
                         "for", retry["room"], "target=legacy", "id=", retry_id)
                return True
            except Exception as exc:
                self.pending_lists.pop(retry_id, None)
                self.log("[INV] legacy roster retry failed:", repr(exc))
        else:
            self.pending_lists.pop(request_id, None)
            self.invite_request_timers.pop(request_id, None)
        self._abort_invite_job(
            key,
            "⚠️ لم تصل قوائم الأعضاء من الخادم بعد محاولتين؛ لم تُرسل أي دعوة. أعد الأمر لاحقاً.",
        )
        return False

    def decode_user_candidate(self, item, depth=0):
        """Decode the native Talkin APK UserItem format, following Kofi Bot."""
        if depth > 7 or item is None:
            return []
        if isinstance(item, bytes):
            try:
                return self.decode_user_candidate(decode_message(item), depth + 1)
            except Exception:
                return []
        if isinstance(item, (list, tuple)):
            out = []
            for child in item:
                out.extend(self.decode_user_candidate(child, depth + 1))
            return out
        if not isinstance(item, dict):
            return []

        def field(number, *aliases):
            for key in (number, str(number), *aliases):
                if key in item and item.get(key) is not None:
                    value = item.get(key)
                    if isinstance(value, list):
                        value = value[0] if value else ""
                    if isinstance(value, bytes):
                        try:
                            value = value.decode("utf-8")
                        except UnicodeDecodeError:
                            value = ""
                    return str(value).strip()
            return ""

        name = field(1, "username", "user_name", "nick", "name").lstrip("@")
        role = field(6, "role", "user_role").strip().lower()
        user_id = field(2, "user_id", "uid", "id")
        online = field(5, "online", "is_online", "is_present")
        has_metadata = any(k in item or str(k) in item for k in (2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12))
        if name and (has_metadata or set(item.keys()).issubset({1, "1", "username", "user_name", "nick", "name"})):
            return [{"username": name, "role": role or "none", "user_id": user_id, "online": online}]

        out = []
        for child in item.values():
            out.extend(self.decode_user_candidate(child, depth + 1))
        return out

    def extract_room_list_users(self, result):
        """Read ResultMessage.users[] first, then RoomAdmin legacy wrappers."""
        candidates = []
        raw_users = result.get("users") or []
        if isinstance(raw_users, dict):
            candidates.append(raw_users)
        elif isinstance(raw_users, (list, tuple)):
            candidates.extend(raw_users)
        elif raw_users:
            candidates.append(raw_users)
        room_admin = result.get("room_admin") or {}
        if isinstance(room_admin, dict):
            for field_no in (11, 10):
                raw = room_admin.get(field_no) or room_admin.get(str(field_no)) or []
                candidates.extend(raw if isinstance(raw, (list, tuple)) else [raw])
            for key, value in room_admin.items():
                if key in (10, 11, "10", "11"):
                    continue
                if isinstance(value, (bytes, list, tuple, dict)):
                    candidates.append(value)

        users = []
        seen = set()
        for candidate in candidates:
            for user in self.decode_user_candidate(candidate):
                name = str(user.get("username") or "").strip().lstrip("@")
                key = norm(name)
                if name and key and key != norm(BOT_ID) and key not in seen:
                    seen.add(key)
                    user["username"] = name
                    users.append(user)
        return users

    def handle_room_admin(self, result):
        pending = self.pending_owner_imports
        source_room = str(result.get("_occupants_room") or "").strip()
        if pending and source_room and norm(source_room) == norm(pending.get("room")):
            users = self.extract_room_list_users(result)
            owners = []
            explicit_non_owner_roles = {"member", "members", "user", "guest", "admin",
                                        "admins", "moderator", "moderators", "مشرف", "عضو"}
            for user in users:
                role = str(user.get("role") or "none").strip().lower().replace(" ", "_")
                # owners_list is a category-specific Talkin request, as in Kofi.
                # Preserve unknown/numeric role encodings; reject only clearly
                # identified member/admin records from legacy mixed responses.
                if role not in explicit_non_owner_roles:
                    owners.append(user["username"])

            added = []
            for name in owners:
                key = norm(name)
                if key not in self.owners:
                    self.owners[key] = name
                    added.append(name)
            write_json(OWNERS_FILE, self.owners)

            self.pending_owner_imports = {}
            timer = self.owner_import_timer
            self.owner_import_timer = None
            if timer:
                timer.cancel()

            requester = pending.get("requester") or BOT_MASTER
            private = bool(pending.get("private"))
            room = pending.get("room", "")
            self.log(f"[OWNER-IMPORT] room={room} raw={len(users)} owners={len(owners)} added={len(added)} total={len(self.owners)}")
            if owners:
                report = ("✅ تم جلب الأونرات وحفظهم بنجاح.\n"
                          f"👑 عدد الأونرات المستلمة: {len(owners)}\n"
                          f"➕ أسماء جديدة تمت إضافتها: {len(added)}\n"
                          f"📋 إجمالي الأونرات المحفوظة: {len(self.owners)}")
                try:
                    saved_names = sorted(self.owners.values(), key=str.casefold)
                    self.send_room_list(room, "👑 قائمة الأونرات المحفوظة بعد الجلب", saved_names,
                                        "📭 لا توجد أسماء محفوظة.")
                except Exception as exc:
                    self.log("[OWNER-IMPORT] room list display failed:", repr(exc))
            else:
                report = ("⚠️ وصل رد السيرفر، لكن لم أستطع استخراج أسماء الأونرات منه.\n"
                          f"📥 السجلات المقروءة: {len(users)}\n"
                          f"📋 إجمالي الأونرات المحفوظة دون تغيير: {len(self.owners)}\n"
                          "تأكد أن البوت أونر في الغرفة، ثم أعد أمر تحميل الاونرات.")
            try:
                self.reply(room, requester, report, private)
            except Exception as exc:
                self.log("[OWNER-IMPORT] result message failed:", repr(exc))
            return
        if not self.pending_lists: return
        # Prefer an echoed request id when the gateway provides one. If the
        # server omits it, accept an untagged reply only when there is exactly
        # one pending invite request; never steal a reply from another room.
        hinted_ids = {
            str(result.get(name) or "").strip()
            for name in ("uid", "value", "request_id", "id")
            if str(result.get(name) or "").strip()
        }
        matching = [
            req for req, meta in self.pending_lists.items()
            if isinstance(meta, dict) and (
                req in hinted_ids or meta.get("request_id") in hinted_ids
            )
        ]
        if not matching:
            if len(self.pending_lists) != 1:
                self.log("[INV] ignored uncorrelated room_admin reply; pending=", len(self.pending_lists))
                return
            matching = [next(iter(self.pending_lists))]
        req = matching[0]
        meta = self.pending_lists.pop(req)
        if not isinstance(meta, dict):
            self.log("[INV] ignored malformed pending roster metadata")
            return
        timer = self.invite_request_timers.pop(req, None)
        if timer:
            timer.cancel()
        key = meta.get("job_key")
        category = meta.get("category")
        job = self.invite_jobs.get(key)
        if not job: return
        candidates=[]
        rv=result.get("users") or []
        if isinstance(rv,dict): candidates.append(rv)
        elif isinstance(rv,(list,tuple)): candidates.extend(rv)
        ra=result.get("room_admin") or {}
        if isinstance(ra,dict):
            for field_no in (11,10):
                raw=ra.get(field_no) or []
                candidates.extend(raw if isinstance(raw,list) else [raw])
        users=[]; seen=set()
        for item in candidates:
            for user in self.decode_user_candidate(item):
                kuser=norm(user.get("username"))
                if kuser and kuser not in seen:
                    seen.add(kuser); users.append(user)
        if category == "owners_list":
            job["bot_owner"] = any(norm(u["username"]) == norm(BOT_ID) for u in users)
        for user in users:
            name=user["username"]
            if norm(name) != norm(BOT_ID): job["users"][norm(name)] = name
        self.request_next_invite_list(key)

    def handle_invite_list_text(self, room, body):
        """Consume Talkin's human-readable ``User List:`` roster reply.

        Several Talkin gateways return l@o/l@a/l@m as a RoomEvent text rather
        than ResultMessage.users[].  Treat that response as the current
        category response, then continue the exact same three-step collection
        used by binary room_admin replies.
        """
        room = str(room or "").strip()
        body = str(body or "")
        if not room or "user list:" not in body.casefold():
            return False

        category_labels = {
            "owners_list": ("o", ("owners", "owner", "الأونر", "اونر")),
            "admins_list": ("a", ("admins", "admin", "moderator", "المشرف", "مشرف")),
            "members_list": ("m", ("members", "member", "users", "الأعضاء", "اعضاء")),
        }
        match_req = None
        match_meta = None
        expected_label = ""
        for req, meta in list(self.pending_lists.items()):
            if not isinstance(meta, dict) or norm(meta.get("room")) != norm(room):
                continue
            category = str(meta.get("category") or "")
            label, tokens = category_labels.get(category, ("", ()))
            text = body.casefold()
            # If the server labels the response, reject a response belonging
            # to another category; otherwise the unique pending request wins.
            if any(token.casefold() in text for token in tokens):
                match_req, match_meta, expected_label = req, meta, label
                break
            if "user list:" in text and match_req is None:
                match_req, match_meta, expected_label = req, meta, label
        if not match_meta:
            return False

        import re as _re
        users, seen = [], set()
        for line in body.splitlines():
            found = _re.match(r"^\s*\d+[.)]\s+(.+?)\s*$", line.strip())
            if not found:
                continue
            name = found.group(1).strip().lstrip("@").strip()
            key = norm(name)
            if name and key and key != norm(BOT_ID) and key not in seen:
                seen.add(key)
                users.append(name)
        if not users:
            return False

        self.pending_lists.pop(match_req, None)
        timer = self.invite_request_timers.pop(match_req, None)
        if timer:
            timer.cancel()
        job_key = match_meta.get("job_key")
        job = self.invite_jobs.get(job_key)
        if not job:
            return True
        # A native owners-list response is only returned to an authorized
        # room-admin request on the Talkin gateway. Text previews often omit
        # the bot itself, so do not require its name to appear in the numbered
        # preview before continuing the collection.
        if expected_label == "o":
            job["bot_owner"] = True
        for name in users:
            job["users"][norm(name)] = name
        self.log("[INV] consumed RoomEvent User List:", room,
                 match_meta.get("category"), "count=", len(users))
        self.request_next_invite_list(job_key)
        return True

    def finish_invites(self, key, names):
        """Send the configured invitation as a normal private text message."""
        with self.invite_lock:
            job = self.invite_jobs.get(key)
            if not job or job.get("sending"):
                return
            job["sending"] = True
            room = str(job.get("room") or "").strip()

        # De-duplicate while preserving the room-role order. A username can
        # appear in more than one Talkin roster response.
        unique_names = []
        seen = set()
        for raw_name in names or []:
            username = str(raw_name or "").strip().lstrip("@")
            user_key = norm(username)
            if username and user_key and user_key != norm(BOT_ID) and user_key not in seen:
                seen.add(user_key)
                unique_names.append(username)

        private_sent = 0
        failed = 0
        for index, username in enumerate(unique_names):
            # Allow the running job to be cancelled/removed without continuing
            # to message the remaining roster.
            if key not in self.invite_jobs:
                self.log("[INV] stopped before remaining private messages:", room)
                break
            try:
                if self.send_private_invite(username, room) is not True:
                    raise RuntimeError("private text packet was not accepted by the WebSocket")
                private_sent += 1
                self.log("[INV] private text packet queued:", username, "room=", room)
            except Exception as exc:
                failed += 1
                self.log("[INV] private text send failed:", username, repr(exc))
            if index + 1 < len(unique_names) and key in self.invite_jobs:
                time.sleep(INVITE_DELAY)

        # The WebSocket sender can confirm that a packet was written to the
        # connection, but this protocol path has no per-recipient delivery/read
        # receipt. Report queued sends honestly rather than claiming delivery.
        try:
            self.send_room_text(
                room,
                f"✅ انتهت محاولة إرسال الدعوات النصية.\n"
                f"👥 المستلمون في القائمة: {len(unique_names)}\n"
                f"💬 رسائل خاصة أُرسلت عبر الاتصال: {private_sent}\n"
                f"⚠️ تعذر إرسالها: {failed}\n"
                "ℹ️ لا يوفر هذا الاتصال تأكيداً بأن المستلم فتح الرسالة أو استلمها على جهازه.",
            )
        except Exception as exc:
            self.log("[INV] completion notice failed:", repr(exc))
        finally:
            with self.invite_lock:
                self.invite_jobs.pop(key, None)

    def process(self, payload):
        result = decode_result_message(payload)

        # RoomEvent is the authoritative source whenever present. Some Talkin
        # builds attach a ChatMessage wrapper to the same ResultMessage; do not
        # process that wrapper as a PM first, or the room command can be
        # answered privately (and sometimes twice).
        ev = result.get("room_event") or {}
        chat = result.get("chat_message") or {}
        if chat and not ev:
            frm = str(chat.get(3, "") or chat.get(22, "") or
                      chat.get("sender", "") or chat.get("username", "") or
                      chat.get(2, "") or chat.get(1, "") or "").strip()
            chat_body = str(chat.get(5, "") or chat.get("body", "") or
                            chat.get("text", "") or "").strip()
            chat_room = str(chat.get(4, "") or chat.get(13, "") or
                            chat.get("room", "") or "").strip()
            if frm and chat_body:
                known_room = next(
                    (saved for saved in self.rooms if chat_room and norm(chat_room) == norm(saved)),
                    "",
                )
                # A non-empty route that is not the bot's private account route
                # is treated as a room route. The previous code required the
                # room to already exist in rooms.json; if it did not match, it
                # misclassified a room message as private and replied in PM.
                private_routes = {
                    norm(BOT_ID), norm(frm),
                    norm((self.auth or {}).get("user_id", "")),
                }
                private_routes.discard("")
                if known_room:
                    matched_room = known_room
                elif chat_room and norm(chat_room) not in private_routes:
                    matched_room = chat_room
                    if norm(matched_room) not in {norm(x) for x in self.rooms}:
                        self.rooms.add(matched_room)
                        write_json(ROOMS_FILE, sorted(self.rooms))
                        self.log("[ROOM-ROUTE] learned room from inbound ChatMessage route:", matched_room)
                else:
                    matched_room = ""

                if matched_room:
                    self.log("[MASTER-IN] ChatMessage routed as ROOM",
                             "sender=", frm, "room=", repr(matched_room),
                             "body=", chat_body[:100])
                    self.command(matched_room, frm, chat_body, private=False)
                else:
                    self.log("[MASTER-IN] ChatMessage routed as PRIVATE",
                             "sender=", frm, "route=", repr(chat_room),
                             "body=", chat_body[:100])
                    self.command("", frm, chat_body, private=True)
            elif chat:
                self.log("[CHAT] ignored ChatMessage without sender/body; fields=", sorted(chat.keys()))

        if result.get("room_admin") or result.get("users"):
            if not result.get("_occupants_room"):
                if self.pending_owner_imports:
                    result["_occupants_room"] = self.pending_owner_imports.get("room", "")
                elif len(self.pending_lists) == 1:
                    only_meta = next(iter(self.pending_lists.values()))
                    if isinstance(only_meta, dict):
                        result["_occupants_room"] = only_meta.get("room", "")
            self.handle_room_admin(result)

        ev = result.get("room_event") or {}
        if not ev:
            return
        typ = str(ev.get(1) or ev.get("1") or ev.get("type") or "").strip()
        sender = str(ev.get(2) or ev.get("2") or ev.get("sender") or "").strip()
        room = str(ev.get(13) or ev.get("13") or ev.get(4) or ev.get("4") or ev.get("room") or "").strip()
        if not room and len(self.rooms) == 1:
            # Some Talkin builds omit RoomEvent.room on text events. If this
            # session is configured for exactly one room, that is unambiguous.
            room = next(iter(self.rooms))
        if room and norm(room) not in {norm(x) for x in self.rooms}:
            # Receiving a native RoomEvent proves the bot is currently seeing
            # this room; remember its exact route for later ChatMessage frames.
            self.rooms.add(room)
            write_json(ROOMS_FILE, sorted(self.rooms))
            self.log("[ROOM-ROUTE] learned room from native RoomEvent:", room)
        body = str(ev.get(6) or ev.get("6") or ev.get("body") or "").strip()
        # Some gateways spell moderation removal events differently. Keep the
        # original payload fields, but normalize the type for downstream
        # event-specific confirmation logic.
        typ = typ.casefold().strip()
        if typ in {"user_kicked", "member_kicked", "room_kicked", "kicked",
                   "removed", "member_removed"}:
            ev = dict(ev)
            ev.setdefault(31, "outcast")
            typ = "role_changed"

        # User List replies are native roster responses, not ordinary room
        # commands. Consume them before command dispatch so l@o -> l@a -> l@m
        # can advance and eventually start the invitation sender.
        if self.handle_invite_list_text(room, body):
            return

        # In role_changed packets, field 17 is the affected user; field 22
        # can be the acting moderator and must not override the target.
        if typ == "role_changed":
            username = str(ev.get(17, ev.get("17", "")) or "").strip()
        else:
            username = str(ev.get(17, ev.get("17", "")) or
                           ev.get(22, ev.get("22", "")) or sender).strip()

        if typ == "user_joined" and username and norm(username) in self.blacklist:
            try:
                self.change_role(room, username, "outcast")
                self.log("[BLACKLIST] ban requested on join", username, room)
            except Exception as exc:
                self.log("[BLACKLIST] ban failed:", repr(exc))
        elif (typ == "user_joined" and username and self.no_membership_protection_enabled(room)
              and norm(username) not in self.owners
              and norm(username) not in self.masters
              and norm(username) != norm(BOT_ID)
              and self.joined_user_has_no_membership(ev)):
            try:
                self.change_role(room, username, "outcast")
                self.add_blacklist(username)
                self.log("[NO-MEMBERSHIP] ban requested on join", username, room)
                self.send_room_text(room, f"🚫 تم حظر @{username} لدخوله بدون عضوية.")
            except Exception as exc:
                self.log("[NO-MEMBERSHIP] ban failed:", repr(exc))
        elif (typ == "user_joined" and username and self.no_photo_auto_ban
              and norm(username) not in self.owners and norm(username) != norm(BOT_ID)
              and self.joined_user_has_no_photo(ev)):
            try:
                self.change_role(room, username, "outcast")
                self.add_blacklist(username)
                self.log("[NO-PHOTO] ban requested on join", username, room)
            except Exception as exc:
                self.log("[NO-PHOTO] ban failed:", repr(exc))
        elif typ == "user_joined" and username and norm(username) in self.manual_owners:
            try:
                self.change_role(room, username, "owner")
                self.log("[AUTO-OWNER] promotion requested", username, room)
            except Exception as exc:
                self.log("[AUTO-OWNER] failed:", repr(exc))
        elif typ == "role_changed" and username and norm(username) in self.blacklist:
            role = str(ev.get(31, ev.get("31", "")) or ev.get("role", "") or "").strip().lower()
            if role not in ("outcast", "banned", "ban"):
                try:
                    self.change_role(room, username, "outcast")
                    self.log("[BLACKLIST] re-ban requested after role change", username, "role=", role, room)
                except Exception as exc:
                    self.log("[BLACKLIST] re-ban failed:", repr(exc))
        elif typ == "user_left" and username and norm(username) in self.manual_owners:
            try:
                self.change_role(room, username, "member")
                self.log("[AUTO-OWNER] demotion requested", username, room)
            except Exception as exc:
                self.log("[AUTO-OWNER] demotion failed:", repr(exc))

        if typ == "role_changed":
            self._confirm_admin_role_event(room, ev)
        if typ == "text" and body:
            if self._handle_admin_permission_error(room, body):
                return
            self.command(room, sender, body, private=False)

    def _start_heartbeat(self):
        self._stop_heartbeat()
        self._heartbeat_stop = threading.Event()
        interval = max(10.0, float(os.getenv("WS_HEARTBEAT_INTERVAL", "25")))
        def worker():
            while not self._heartbeat_stop.wait(interval):
                try:
                    if self.ws and self.ws.sock:
                        self.ws.send_control(0x9, b"talkin-admin-ping")
                        self.log("[WS] heartbeat ping sent")
                except Exception as exc:
                    self.log("[WS] heartbeat failed:", repr(exc))
                    return
        self._heartbeat_thread = threading.Thread(target=worker, name="ws-heartbeat", daemon=True)
        self._heartbeat_thread.start()

    def _stop_heartbeat(self):
        event = getattr(self, "_heartbeat_stop", None)
        if event:
            event.set()
        thread = getattr(self, "_heartbeat_thread", None)
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=1.0)
        self._heartbeat_stop = None
        self._heartbeat_thread = None

    def run_once(self):
        r = self.http.post(API_BASE_URL + "auth_new", data=encode_auth_request(BOT_ID, BOT_PWD),
            headers={"Content-Type":"application/octet-stream", "User-Agent":"Talkinchat/1.0 (Android 12; net.chatp)"}, timeout=20)
        r.raise_for_status(); self.auth = decode_auth_result(r.content)
        if self.auth.get("result", "").lower() not in ("ok", "success", "true", "1"):
            raise RuntimeError("Authentication rejected: " + str(self.auth.get("message") or self.auth.get("result")))
        self.port = self.auth.get("server") if str(self.auth.get("server", "")).isdigit() else DEFAULT_PORT
        self.captcha_id = self.auth.get("id") or "0"; self.photo_version = self.auth.get("photo_version") or "0"
        raw = f"{self.captcha_id}@{DEVICE_ID}@{DEVICE_MODEL}@android@{LANGUAGE}@{self.photo_version}@0"
        headers = ["b: " + base64.b64encode(raw.encode()).decode()]
        last = None
        for host in WS_HOSTS:
            for path in WS_PATHS:
                try:
                    url = f"wss://{host}:{self.port}{path}"
                    self.ws = RawWebSocket(url, headers, timeout=65, debug=False); self.ws.connect()
                    self._start_heartbeat()
                    self.log("[WS] connected", url)
                    try: self.send_query(encode_query("load_list_new"))
                    except Exception: pass
                    self.join_configured_rooms()
                    while True:
                        try:
                            kind, msg = self.ws.recv()
                        except socket.timeout:
                            # Heartbeat runs independently; an idle room is not a dead session.
                            continue
                        if kind == "binary": self.process(msg)
                        elif kind == "close": raise ConnectionError(f"WebSocket closed: {msg}")
                        elif kind == "oversize": self.log("[WS] dropped oversized inbound packet", msg)
                        elif kind == "ping": self.log("[WS] server ping answered")
                        elif kind == "pong": self.log("[WS] heartbeat pong received")
                except Exception as e:
                    last = e; self.log("[WS] connection failed", host, path, repr(e))
                    self._stop_heartbeat()
                    try:
                        if self.ws: self.ws.close()
                    except Exception: pass
                    self.ws = None
        raise last or RuntimeError("No WebSocket endpoint available")

    def start(self):
        if not BOT_ID or not BOT_PWD or not BOT_MASTER:
            raise SystemExit("Set BOT_ID, BOT_PWD and BOT_MASTER in environment variables.")
        delay = 3
        while True:
            try:
                self.run_once()
                delay = 3
            except KeyboardInterrupt:
                self._stop_heartbeat()
                return
            except Exception as e:
                self._stop_heartbeat()
                self.log("[RECONNECT]", repr(e), "retry_in=", delay)
                time.sleep(delay)
                delay = min(60, delay * 2)

if __name__ == "__main__":
    TalkinAdminBot().start()
