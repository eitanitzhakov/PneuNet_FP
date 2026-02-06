import socket
import threading
import struct
import base64
import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, Optional, Tuple

from json_protocol import JsonProtocol, SecureJsonProtocol
from cipher import Cipher
from db import DB
from constants import NONCE
from Prediction import Predictor


class Server:
    def __init__(self, host: str = "0.0.0.0", port: int = 8080, backlog: int = 100, timeout_sec: int = 60,
                 max_clients: int = 200, weights_path: str = r"C:\Users\eitan\Downloads\best_ft.pth",
                 arch: str = "tf_efficientnet_b4_ns", img_size: int = 380, device: Optional[str] = None, ):
        self.host = host
        self.port = port
        self.backlog = backlog
        self.timeout_sec = timeout_sec
        self.max_clients = max_clients
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.protocol = JsonProtocol()

        # request_id -> path
        self.upload_index: Dict[str, str] = {}
        self._upload_lock = threading.Lock()

        # DB init
        self.db = DB()

        try:
            self.predictor = Predictor(
                weights_path=weights_path,
                arch=arch,
                img_size=img_size,
                device=device,
            )
            print(f"[SERVER] Model loaded. arch={arch}")
        except Exception as e:
            print(f"[SERVER] Warning: Failed to load model: {e}")
            self.predictor = None

        self._executor = ThreadPoolExecutor(max_workers=self.max_clients)
        self._shutdown = threading.Event()

    def start(self) -> None:
        self.sock.bind((self.host, self.port))
        self.sock.listen(self.backlog)
        print(f"[SERVER] Listening on {self.host}:{self.port} (max_clients={self.max_clients})")

        try:
            while not self._shutdown.is_set():
                client_sock, addr = self.sock.accept()
                self._executor.submit(self.handle_client, client_sock, addr)
        except KeyboardInterrupt:
            print("[SERVER] KeyboardInterrupt -> shutting down")
        finally:
            self.stop()

    def stop(self) -> None:
        self._shutdown.set()
        try:
            self.sock.close()
        except Exception:
            pass
        try:
            self._executor.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass
        try:
            self.db.close()
        except Exception:
            pass
        print("[SERVER] Stopped")

    def handle_client(self, client_sock: socket.socket, addr: Tuple[str, int]) -> None:
        print(f"[SERVER] Connection from {addr}")
        try:
            client_sock.settimeout(self.timeout_sec)
            with client_sock:
                # key handshake
                dh_server, pk_server = Cipher.get_dh_public_key()
                pk_server_b64 = base64.b64encode(pk_server).decode("ascii")

                self.protocol.send(client_sock, {
                    "type": "DH_SERVER_PK",
                    "pk": pk_server_b64
                })

                msg = self.protocol.recv(client_sock)
                if not msg or msg.get("type") != "DH_CLIENT_PK":
                    print(f"[SERVER] Handshake failed {addr}")
                    return

                pk_client = base64.b64decode(msg.get("pk").encode("ascii"))
                shared_key = Cipher.get_dh_shared_key(dh_server, pk_client, lngth=32)

                cipher = Cipher(shared_key, NONCE)
                secure_protocol = SecureJsonProtocol(self.protocol, cipher)

                secure_protocol.send(client_sock, {"type": "SECURE_OK"})

                current_user_id: Optional[int] = None

                while True:
                    msg = secure_protocol.recv(client_sock)
                    if msg is None:
                        break  # client is not on anymore

                    resp, should_close, current_user_id = self.on_message(client_sock, msg, secure_protocol, cipher,
                                                                          current_user_id)

                    if resp is not None:
                        secure_protocol.send(client_sock, resp)

                    if should_close:
                        secure_protocol.send(client_sock, {"type": "BYE"})
                        break

        except Exception as e:
            print(f"[SERVER] Client error {addr}: {e}")

    def on_message(self, client_sock: socket.socket, msg: Dict[str, Any], secure_protocol: SecureJsonProtocol,
                   cipher: Cipher, user_id: Optional[int]) -> Tuple[Optional[Dict[str, Any]], bool, Optional[int]]:

        mtype = str(msg.get("type", "")).upper().strip()
        actual_sha = ""
        if mtype == "PING":
            return {"type": "PONG"}, False, user_id

        if mtype == "SIGNUP":
            username = msg.get("username")
            password = msg.get("password")
            if self.db.signup(username, password):
                return {"type": "SIGNUP_OK"}, False, user_id
            return {"type": "ERROR", "message": "Signup failed"}, False, user_id

        if mtype == "LOGIN":
            username = msg.get("username")
            password = msg.get("password")
            uid = self.db.login(username, password)
            if uid:
                return {"type": "LOGIN_OK", "user_id": uid}, False, uid
            return {"type": "ERROR", "message": "Login failed"}, False, user_id

        if user_id is None and mtype != "CLOSE":
            return {"type": "ERROR", "message": "Auth required"}, False, user_id

        if mtype == "UPLOAD":
            request_id = str(msg.get("request_id") or "").strip()
            file_size = int(msg.get("file_size", 0))
            ext = str(msg.get("ext", "bin")).strip()
            expected_sha = str(msg.get("sha256", "")).strip()
            patient_id = str(msg.get("patient_id") or "Unknown").strip()

            if not request_id or file_size <= 0:
                return {"type": "ERROR", "message": "Invalid upload parameters"}, False, user_id

            secure_protocol.send(client_sock, {"type": "READY", "request_id": request_id})

            save_dir = "uploads"
            os.makedirs(save_dir, exist_ok=True)
            path = os.path.join(save_dir, f"{request_id}.{ext}")

            try:
                self._receive_encrypted_file(client_sock, path, file_size, cipher)
            except Exception as e:
                return {"type": "ERROR", "message": f"Upload failed: {str(e)}"}, False, user_id

            if expected_sha:  # only if hash was sent
                actual_sha = self._calc_file_hash(path)
                if actual_sha != expected_sha:
                    os.remove(path)
                    return {"type": "ERROR", "message": "Integrity check failed (SHA mismatch)"}, False, user_id

            if not actual_sha:
                actual_sha = self._calc_file_hash(path)

            # שמירה ל-DB ללא file_path
            if not self.db.save_new_scan(request_id, user_id, actual_sha, patient_id):
                return {"type": "ERROR", "message": "DB Error"}, False, user_id

            with self._upload_lock:
                self.upload_index[request_id] = path

            return {
                "type": "UPLOAD_OK",
                "request_id": request_id,
                "sha256": actual_sha
            }, False, user_id

        if mtype == "PREDICT":
            request_id = str(msg.get("request_id") or "").strip()
            if not request_id:
                return {"type": "ERROR", "message": "missing request_id"}, False, user_id

            path = ""
            with self._upload_lock:
                path = self.upload_index.get(request_id)

            if not path or not os.path.exists(path):
                return {"type": "ERROR", "message": "File not found. Upload first."}, False, user_id

            if not self.predictor:
                return {"type": "ERROR", "message": "Model not loaded"}, False, user_id

            try:
                prediction = self.predictor.predict(path)

                # עדכון התוצאה ב-DB
                self.db.update_scan(request_id, str(prediction.get("label")), float(prediction.get("confidence", 0)))

                # === מחיקת הקובץ והסרתו מהזיכרון ===
                try:
                    os.remove(path)
                except Exception as e:
                    print(f"[SERVER] Error deleting file {path}: {e}")

                with self._upload_lock:
                    if request_id in self.upload_index:
                        del self.upload_index[request_id]
                # =================================

                return {
                    "type": "PREDICT_OK",
                    "request_id": request_id,
                    "prediction": prediction,
                }, False, user_id
            except Exception as e:
                self.db.mark_scan_error(request_id)
                return {"type": "ERROR", "message": f"Prediction failed: {e}"}, False, user_id

        if mtype == "HISTORY":
            return {"type": "HISTORY_OK", "history": self.db.get_user_history(user_id)}, False, user_id

        if mtype == "CLOSE":
            return {"type": "BYE"}, True, user_id

        return {"type": "OK"}, False, user_id

    def _receive_encrypted_file(self, sock: socket.socket, path: str, total_size: int, cipher: Cipher):
        received_bytes_original = 0

        with open(path, "wb") as f:
            while received_bytes_original < total_size:
                header = self._recv_exact(sock, 4)
                if not header:
                    raise ConnectionError("Connection lost reading header")

                (chunk_len,) = struct.unpack(">I", header)

                encrypted_chunk = self._recv_exact(sock, chunk_len)
                if not encrypted_chunk:
                    raise ConnectionError("Connection lost reading chunk")

                try:
                    b64_str = cipher.aes_decrypt(encrypted_chunk)
                    raw_bytes = base64.b64decode(b64_str)
                    f.write(raw_bytes)
                    received_bytes_original += len(raw_bytes)
                except Exception as e:
                    raise RuntimeError(f"Decryption failed: {e}")

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    @staticmethod
    def _calc_file_hash(path: str) -> str:
        sha = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                sha.update(chunk)
        return sha.hexdigest()