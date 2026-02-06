import socket
import json
import struct
from typing import Any, Dict, Optional
import base64

class JsonProtocol:
    #256KB max size
    def __init__(self, max_message_bytes: int = 262144):
        self.max_message_bytes = max_message_bytes

    #ext - is the file type[jpeg,dcm...]
    def send(self, sock: socket.socket, obj: Dict[str, Any]) -> None:
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        if len(data) > self.max_message_bytes:
            raise ValueError("json message is too large")

        #header purpose to define the data length
        header = struct.pack(">I", len(data))
        sock.sendall(header + data)

    def recv(self, sock: socket.socket) -> Optional[Dict[str, Any]]:
        header = self._recv_exact(sock, 4)
        if header is None:
            return None

        (length,) = struct.unpack(">I", header)
        if length <= 0 or length > self.max_message_bytes:
            raise ValueError("invalid json length: {}".format(length))

        payload = self._recv_exact(sock, length)
        if payload is None:
            return None

        return json.loads(payload.decode("utf-8"))

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data



class SecureJsonProtocol:
    def __init__(self, inner_protocol, cipher):
        self.inner = inner_protocol
        self.cipher = cipher

    def send(self, sock, obj: Dict[str, Any]) -> None:
        plain = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        ct = self.cipher.aes_encrypt(plain)
        b64 = base64.b64encode(ct).decode("ascii")
        self.inner.send(sock, {"type": "ENC", "payload": b64})

    def recv(self, sock) -> Optional[Dict[str, Any]]:
        wrapper = self.inner.recv(sock)
        if wrapper is None:
            return None

        if str(wrapper.get("type", "")).upper() != "ENC":
            raise ValueError("non encrypted message received after handshake")

        b64 = wrapper.get("payload", "")
        ct = base64.b64decode(b64.encode("ascii"))
        plain_str = self.cipher.aes_decrypt(ct)
        return json.loads(plain_str)

