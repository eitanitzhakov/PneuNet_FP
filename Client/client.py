from constants import NONCE
from json_protocol import JsonProtocol, SecureJsonProtocol
from cipher import Cipher
import socket
import  struct
import base64
import hashlib
import os
import uuid
from typing import Dict, Any, Optional, Callable

class Client:
    CHUNK_SIZE = 65536

    def __init__(self, host: str, port: int, timeout_sec: int = 60):
        self.host = host
        self.port = port
        self.timeout_sec = timeout_sec
        self.sock: Optional[socket.socket] = None
        self.proto = JsonProtocol()
        self.secure: Optional[SecureJsonProtocol] = None
        self.is_connected = False

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()


    def connect(self) -> None:
        if self.is_connected:
            return

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout_sec)
            self.sock.connect((self.host, self.port))

            # pk from the server
            msg = self.proto.recv(self.sock)
            if not msg or msg.get("type") != "DH_SERVER_PK":
                raise ConnectionError("Handshake failed: Invalid server Hello")
            # decoding
            server_pk_bytes = base64.b64decode(msg["pk"])
            # client keys
            client_dh, client_pk = Cipher.get_dh_public_key()
            shared_key = Cipher.get_dh_shared_key(client_dh, server_pk_bytes, length=32)
            # send pk
            client_pk_b64 = base64.b64encode(client_pk).decode("ascii")
            self.proto.send(self.sock, {"type": "DH_CLIENT_PK", "pk": client_pk_b64})
            # starting the secure protocols
            cipher = Cipher(shared_key, NONCE)
            self.secure = SecureJsonProtocol(self.proto, cipher)
            # test if secured
            ok_msg = self._secure_recv()
            self._expect(ok_msg, "SECURE_OK")

            self.is_connected = True

        except Exception as e:
            self.close()
            raise ConnectionError(f"Failed to connect: {e}")

    def close(self) -> None:
        if self.sock:
            try:
                if self.is_connected and self.secure:
                    self.secure.send(self.sock, {"type": "CLOSE"})
            except Exception:
                pass
            finally:
                self.sock.close()
                self.sock = None
                self.is_connected = False

    def signup(self, username, password):
        self._secure_send({"type": "SIGNUP", "username": username, "password": password})
        return self._expect(self._secure_recv(), "SIGNUP_OK")

    def login(self, username, password):
        self._secure_send({"type": "LOGIN", "username": username, "password": password})
        resp = self._expect(self._secure_recv(), "LOGIN_OK")
        return resp

    def get_history(self):
        self._secure_send({"type": "HISTORY"})
        return self._expect(self._secure_recv(), "HISTORY_OK")

    def ping(self) -> Dict[str, Any]:
        self._secure_send({"type": "PING"})
        return self._expect(self._secure_recv(), "PONG")

    def predict(self, request_id: str) -> Dict[str, Any]:
        if not request_id:
            raise ValueError("Request ID required")
        self._secure_send({"type": "PREDICT", "request_id": request_id})
        return self._expect(self._secure_recv(), "PREDICT_OK")

    def upload(self, file_path: str, patient_id: str, request_id: Optional[str] = None,
               on_progress: Optional[Callable[[int, int], None]] = None) -> Dict[
        str, Any]:  # the callable gets[current bytes, total bytes]
        sock = self._ensure_connected()  # checks if connected
        meta = self._prepare_upload_metadata(file_path, request_id)
        # Added: Pass patient_id
        self._perform_upload_handshake(meta, patient_id)
        self._stream_encrypted_file(sock, file_path, meta["file_size"], on_progress)  # sends the file itself
        return self._finalize_upload(meta["sha256"], meta["request_id"])  # checks id and hash are the same


    def _ensure_connected(self) -> socket.socket:
        if not self.is_connected or not self.sock:
            raise RuntimeError("Client not connected")
        return self.sock

    def _secure_send(self, obj: Dict[str, Any]) -> None:
        if not self.secure:
            raise RuntimeError("Secure channel not established")
        self.secure.send(self.sock, obj)

    def _secure_recv(self) -> Dict[str, Any]:
        if not self.secure:
            raise RuntimeError("Secure channel not established")
        msg = self.secure.recv(self.sock)
        if msg is None:
            raise ConnectionError("Server closed connection")
        if str(msg.get("type", "")).upper() == "ERROR":
            raise RuntimeError(f"Server Error: {msg.get('message')}")
        return msg

    def _expect(self, msg: Dict[str, Any], expected_type: str) -> Dict[str, Any]:
        if not msg or msg.get("type") != expected_type:
            raise RuntimeError(f"Expected {expected_type}, got {msg.get('type')}")
        return msg


    def _prepare_upload_metadata(self, file_path: str, req_id: Optional[str]) -> Dict[str, Any]:
        if not os.path.exists(file_path):
            raise FileNotFoundError(file_path)

        file_size = os.path.getsize(file_path)
        req_id = req_id if req_id else uuid.uuid4().hex #generates the req_id
        ext = os.path.splitext(file_path)[1].lstrip(".").lower() or "bin"

        # making hash for the file - for checksum reasons
        sha = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(self.CHUNK_SIZE):
                sha.update(chunk)
        return {
            "request_id": req_id,
            "file_size": file_size,
            "ext": ext,
            "sha256": sha.hexdigest()
        }

    # Added: Handshake with patient_id
    def _perform_upload_handshake(self, meta: Dict[str, Any], patient_id: str) -> None:
        payload = {
            "type": "UPLOAD",
            "request_id": meta["request_id"],
            "file_size": meta["file_size"],
            "ext": meta["ext"],
            "sha256": meta["sha256"],
            "patient_id": patient_id, # Added field
            "encrypted_stream": True
        }
        self._secure_send(payload)
        # wait for confirmation ready from server
        resp = self._secure_recv()
        self._expect(resp, "READY")
        if resp.get("request_id") != meta["request_id"]:
            raise RuntimeError("Handshake ID mismatch")  # not same id

    def _stream_encrypted_file(self, sock: socket.socket, path: str, total_size: int,
                               on_progress: Optional[Callable[[int, int], None]]) -> None:
        # reads file -> base64 -> encryption -> adding header -> sends -> updates the on progress
        read_size = 65536  # Using 64KB as buffer
        sent_bytes_original = 0

        with open(path, "rb") as f:
            while True:
                raw_chunk = f.read(read_size)
                if not raw_chunk:
                    break
                # base64 the chunks so it will be sent in bytes
                b64_chunk = base64.b64encode(raw_chunk)
                # encryption
                encrypted_chunk = self.secure.cipher.aes_encrypt(b64_chunk)
                # [len][payload] -> [header][payload]
                header = struct.pack(">I", len(encrypted_chunk))
                sock.sendall(header + encrypted_chunk)
                # update on_progress
                sent_bytes_original += len(raw_chunk)
                if on_progress:
                    on_progress(sent_bytes_original, total_size)

    def _finalize_upload(self, local_sha: str, req_id: str) -> Dict[str, Any]:
        resp = self._secure_recv()
        self._expect(resp, "UPLOAD_OK")

        received_id = resp.get("request_id")
        if received_id != req_id:
            raise RuntimeError(f"Upload ID mismatch: expected {req_id}, got {received_id}")

        # check if same hash -> from MITM or lost of data
        if local_sha:
            server_sha = str(resp.get("sha256", "")).strip()
            if server_sha and server_sha != local_sha:
                raise RuntimeError(f"Integrity check failed: Client={local_sha}, Server={server_sha}")
            elif not server_sha:  # the server didn't return the hash
                pass
        return resp