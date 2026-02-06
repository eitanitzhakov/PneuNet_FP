import sys
import os
import time
from datetime import datetime

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

try:
    from client import Client
except ImportError as e:
    print(f"Critical Error: Could not import 'Client' from parent directory.\nDetails: {e}")
    # Fallback mock for UI testing if client is missing
    Client = None

from PySide6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QFrame,
    QVBoxLayout, QHBoxLayout, QMessageBox, QFileDialog, QListWidget,
    QListWidgetItem, QTextEdit, QInputDialog, QProgressBar
)
from PySide6.QtCore import Qt, QPropertyAnimation, QEasingCurve, QPoint, Signal, QThread, Slot
from PySide6.QtGui import QCursor

from zxcvbn import zxcvbn



class Worker(QThread):
    finished = Signal(object)  # Returns result (dict/bool/str)
    error = Signal(str)  # Returns error message

    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs

    def run(self):
        try:
            result = self.func(*self.args, **self.kwargs)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))

def password_is_strong(pw: str) -> tuple[bool, str]:
    if not pw:
        return False, "Enter a password."
    r = zxcvbn(pw)
    score = r.get("score", 0)
    feedback = r.get("feedback", {}) or {}
    warning = (feedback.get("warning") or "").strip()
    suggestions = " ".join(feedback.get("suggestions") or []).strip()

    if score >= 3:
        return True, "Strong password "

    msg = warning or "Password is too weak."
    if suggestions:
        msg = f"{msg} {suggestions}"
    return False, msg



class HistoryPanel(QFrame):
    itemSelected = Signal(dict)  # Emits the full history item dict

    def __init__(self):
        super().__init__()
        self.setObjectName("HistoryPanel")
        self.setMinimumWidth(260)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        title = QLabel("History")
        title.setObjectName("PanelTitle")

        self.listw = QListWidget()
        self.listw.itemClicked.connect(self._on_item_clicked)

        hint = QLabel("Select a previous run to view its result.")
        hint.setObjectName("HintText")
        hint.setWordWrap(True)

        layout.addWidget(title)
        layout.addWidget(self.listw, 1)
        layout.addWidget(hint)

    def load_items(self, history_list: list):
        self.listw.clear()
        # Expecting list of dicts from server
        # Example: {'request_id': '...', 'timestamp': '...', 'prediction': '...'}
        for item_data in history_list:
            req_id = item_data.get('request_id', '???')[:8]
            ts = item_data.get('timestamp', '')

            display_text = f"{ts} | {req_id}"
            item = QListWidgetItem(display_text)
            item.setData(Qt.ItemDataRole.UserRole, item_data)
            self.listw.addItem(item)

    def _on_item_clicked(self, item: QListWidgetItem):
        data = item.data(Qt.ItemDataRole.UserRole)
        if data:
            self.itemSelected.emit(data)


class UploadPanel(QFrame):
    runRequested = Signal(str)  # Emits "filepath||patient_id"

    def __init__(self):
        super().__init__()
        self.setObjectName("UploadPanel")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        title = QLabel("Upload File")
        title.setObjectName("PanelTitle")

        desc = QLabel("Add a medical scan (Image/DCM/etc).")
        desc.setObjectName("HintText")
        desc.setWordWrap(True)

        self.path_lbl = QLabel("No file selected")
        self.path_lbl.setObjectName("PathLabel")
        self.path_lbl.setWordWrap(True)

        self.btn_choose = QPushButton("Choose File")
        self.btn_choose.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_choose.clicked.connect(self.choose_file)

        self.btn_run = QPushButton("Run Analysis")
        self.btn_run.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_run.clicked.connect(self.run_analysis)
        self.btn_run.setEnabled(False)

        # Progress bar
        self.pbar = QProgressBar()
        self.pbar.setValue(0)
        self.pbar.setVisible(False)
        self.pbar.setStyleSheet(
            "QProgressBar { height: 10px; border-radius: 5px; } QProgressBar::chunk { background-color: #007acc; border-radius: 5px; }")

        layout.addWidget(title)
        layout.addWidget(desc)
        layout.addSpacing(6)
        layout.addWidget(self.path_lbl)
        layout.addSpacing(6)
        layout.addWidget(self.btn_choose)
        layout.addWidget(self.btn_run)
        layout.addWidget(self.pbar)
        layout.addStretch()

        self._selected_path = ""

    def choose_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select file",
            "",
            "Images (*.png *.jpg *.jpeg *.bmp *.dcm);;All files (*.*)"
        )
        if path:
            self._selected_path = path
            self.path_lbl.setText(os.path.basename(path))
            self.btn_run.setEnabled(True)
            self.pbar.setVisible(False)

    def run_analysis(self):
        if not self._selected_path:
            QMessageBox.warning(self, "Missing file", "Please choose a file first.")
            return

        patient_id, ok = QInputDialog.getText(
            self,
            "Patient Identification",
            "Enter Patient ID Number:"
        )
        if not ok:
            return

        patient_id = patient_id.strip()
        if not patient_id:
            QMessageBox.warning(self, "Invalid Input", "Patient ID cannot be empty.")
            return

        self.runRequested.emit(f"{self._selected_path}||{patient_id}")

    def set_loading(self, loading: bool):
        self.btn_run.setEnabled(not loading)
        self.btn_choose.setEnabled(not loading)
        self.pbar.setVisible(loading)
        if loading:
            self.pbar.setRange(0, 0)  # Infinite loading animation until we implement real progress
        else:
            self.pbar.setRange(0, 100)
            self.pbar.setValue(0)


class ResultPanel(QFrame):
    def __init__(self):
        super().__init__()
        self.setObjectName("ResultPanel")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        title = QLabel("Analysis Result")
        title.setObjectName("PanelTitle")

        self.result_box = QTextEdit()
        self.result_box.setReadOnly(True)
        self.result_box.setPlaceholderText("Results will appear here after you run analysis...")

        layout.addWidget(title)
        layout.addWidget(self.result_box, 1)

    def display_prediction(self, pred_data: dict, patient_id: str = "", file_name: str = ""):
        # pred_data example: {'request_id': '...', 'prediction': {'label': 'Healthy', 'confidence': 0.95}}

        prediction = pred_data.get("prediction", {})
        label = prediction.get("label", "Unknown")
        conf = float(prediction.get("confidence", 0.0)) * 100

        ts = datetime.now().strftime("%Y-%m-%d %H:%M")

        html = f"""
        <h3 style="color: #007acc;">Analysis Complete</h3>
        <p><b>Date:</b> {ts}</p>
        <p><b>Patient ID:</b> {patient_id}</p>
        <p><b>File:</b> {file_name}</p>
        <hr>
        <h2 style="color: #222;">Diagnosis: {label}</h2>
        <p style="font-size: 14px;">Confidence: <b>{conf:.2f}%</b></p>
        """
        self.result_box.setHtml(html)

    def display_history_item(self, data: dict):
        # Format history item raw data
        import json
        pretty = json.dumps(data, indent=2, ensure_ascii=False)
        self.result_box.setPlainText(pretty)


class HomeWindow(QWidget):
    def __init__(self, client: Client, username: str = ""):
        super().__init__()
        self.client = client
        self.username = username
        self.setWindowTitle("PneuNet - Dashboard")
        self.resize(1100, 650)

        self.setStyleSheet("""
            QWidget { background-color: #f5f7fa; font-family: 'Segoe UI'; }
            QFrame#TopBar { background: white; border: 1px solid #e6e8ee; border-radius: 14px; }
            QFrame#HistoryPanel, QFrame#UploadPanel, QFrame#ResultPanel {
                background: white; border: 1px solid #e6e8ee; border-radius: 16px;
            }
            QLabel#PanelTitle { font-size: 16px; font-weight: 700; color: #222; }
            QLabel#HintText { color: #6b7280; font-size: 12px; }
            QLabel#PathLabel {
                color: #111827; font-size: 12px; background: #f3f4f6;
                padding: 8px; border-radius: 10px;
            }
            QListWidget { border: 1px solid #eef0f5; border-radius: 12px; padding: 6px; background: #fbfcff; }
            QTextEdit {
                border: 1px solid #eef0f5; border-radius: 12px; padding: 10px;
                background: #fbfcff; font-size: 13px; color: #111;
            }
            QPushButton {
                background-color: #007acc; color: white; font-weight: bold;
                border-radius: 10px; padding: 10px; font-size: 14px; border: 1px solid #005c99;
            }
            QPushButton:hover { background-color: #005c99; }
            QPushButton:pressed { background-color: #004080; }
            QPushButton:disabled { background-color: #9ca3af; border: 1px solid #9ca3af; }
        """)

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 18, 18, 18)
        root.setSpacing(12)

        top = QFrame()
        top.setObjectName("TopBar")
        top_l = QHBoxLayout(top)
        top_l.setContentsMargins(14, 10, 14, 10)

        brand = QLabel("PneuNet")
        brand.setStyleSheet("font-size: 18px; font-weight: 900; color: #111827;")

        user_lbl = QLabel(f"Signed in as: {username or 'User'}")
        user_lbl.setStyleSheet("color: #6b7280; font-size: 12px;")

        top_l.addWidget(brand)
        top_l.addStretch()
        top_l.addWidget(user_lbl)

        row = QHBoxLayout()
        row.setSpacing(12)

        self.history = HistoryPanel()
        self.upload = UploadPanel()
        self.upload.setMinimumWidth(320)
        self.result = ResultPanel()
        self.result.setMinimumWidth(420)

        row.addWidget(self.result, 2)
        row.addWidget(self.upload, 1)
        row.addWidget(self.history, 1)

        root.addWidget(top)
        root.addLayout(row, 1)

        self.upload.runRequested.connect(self.on_run_requested)
        self.history.itemSelected.connect(self.result.display_history_item)

        # Load history on startup
        self.refresh_history()

    def refresh_history(self):
        self.history_worker = Worker(self.client.get_history)
        self.history_worker.finished.connect(self._on_history_loaded)
        self.history_worker.start()

    def _on_history_loaded(self, resp):
        # Server returns {"type": "HISTORY_OK", "history": [...]}
        if resp and resp.get("type") == "HISTORY_OK":
            items = resp.get("history", [])
            self.history.load_items(items)

    def on_run_requested(self, payload: str):
        try:
            file_path, patient_id = payload.split("||", 1)
        except ValueError:
            return

        self.upload.set_loading(True)
        self.result.result_box.setPlainText("Processing... Uploading and Analyzing...")

        # Run Upload + Predict in background
        self.worker = Worker(self._process_analysis, file_path, patient_id)
        self.worker.finished.connect(lambda res: self._on_analysis_finished(res, file_path, patient_id))
        self.worker.error.connect(self._on_analysis_error)
        self.worker.start()

    def _process_analysis(self, path, pid):
        # 1. Upload
        upload_resp = self.client.upload(path, pid)
        req_id = upload_resp.get("request_id")
        if not req_id:
            raise RuntimeError("Upload failed, no Request ID returned.")

        # 2. Predict
        predict_resp = self.client.predict(req_id)
        return predict_resp

    def _on_analysis_finished(self, result, path, pid):
        self.upload.set_loading(False)
        self.result.display_prediction(result, pid, os.path.basename(path))
        self.refresh_history()  # Update list with new item

    def _on_analysis_error(self, err_msg):
        self.upload.set_loading(False)
        QMessageBox.critical(self, "Analysis Failed", f"Error: {err_msg}")
        self.result.result_box.setPlainText(f"Error occurred:\n{err_msg}")


class AuthWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Medical Login System")
        self.resize(900, 550)
        self.setStyleSheet("background-color: #f0f2f5; font-family: 'Segoe UI';")

        # Initialize Client (Assuming server is local for now)
        # You can change host/port here
        try:
            if Client:
                self.client = Client(host="127.0.0.1", port=8080)
            else:
                self.client = None  # Handling missing file
        except Exception as e:
            QMessageBox.critical(self, "Init Error", str(e))

        self.container = QFrame(self)
        self.container.setGeometry(50, 50, 800, 450)
        self.container.setStyleSheet("background-color: white; border-radius: 20px; border: 1px solid #ddd;")

        self.setup_signup_form()
        self.setup_login_form()
        self.setup_overlay()

        self.home_window = None

    # ... (setup_signup_form and setup_login_form code remains largely the same, mostly UI) ...
    # I will include them to ensure the full file is copy-pasteable

    def setup_signup_form(self):
        self.signup_widget = QFrame(self.container)
        self.signup_widget.setGeometry(0, 0, 400, 450)
        self.signup_widget.setStyleSheet("background-color: transparent; border: none;")
        layout = QVBoxLayout(self.signup_widget)
        layout.setContentsMargins(50, 50, 50, 50)

        title = QLabel("Create Account")
        title.setStyleSheet("font-size: 28px; font-weight: bold; color: #333;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        layout.addSpacing(20)

        self.reg_name = QLineEdit(placeholderText="Full Name (Username)")
        self.reg_email = QLineEdit(placeholderText="Email (Optional)")
        self.reg_pass = QLineEdit(placeholderText="Password")
        self.reg_pass.setEchoMode(QLineEdit.EchoMode.Password)

        for le in [self.reg_name, self.reg_email, self.reg_pass]:
            le.setStyleSheet("border: none; border-bottom: 2px solid #ccc; padding: 8px; font-size: 14px;")
            layout.addWidget(le)

        self.pw_status = QLabel("Password strength: waiting...")
        self.pw_status.setStyleSheet("color: #666; font-size: 12px;")
        layout.addWidget(self.pw_status)
        layout.addSpacing(18)

        self.btn_signup = QPushButton("SIGN UP")
        self.btn_signup.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_signup.setStyleSheet("""
            QPushButton { background-color: #007acc; color: white; border-radius: 10px; padding: 12px; font-weight: bold;}
            QPushButton:hover { background-color: #005c99; }
            QPushButton:disabled { background-color: #9ca3af; }
        """)
        self.btn_signup.clicked.connect(self.handle_signup_click)
        layout.addWidget(self.btn_signup)
        self.btn_signup.setEnabled(False)
        self.reg_pass.textChanged.connect(self.on_password_changed)
        layout.addStretch()

        btn_switch = QPushButton("Already have an account? Login")
        btn_switch.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn_switch.setStyleSheet("color: #666; border: none; font-weight: bold; background: transparent;")
        btn_switch.clicked.connect(self.animate_to_login)
        layout.addWidget(btn_switch, alignment=Qt.AlignmentFlag.AlignCenter)

    def on_password_changed(self, text: str):
        ok, msg = password_is_strong(text)
        if ok:
            self.pw_status.setText(msg)
            self.pw_status.setStyleSheet("color: #16a34a; font-size: 12px; font-weight: 600;")
            self.btn_signup.setEnabled(True)
        else:
            self.pw_status.setText(f"Weak password: {msg}")
            self.pw_status.setStyleSheet("color: #dc2626; font-size: 12px; font-weight: 600;")
            self.btn_signup.setEnabled(False)

    def setup_login_form(self):
        self.login_widget = QFrame(self.container)
        self.login_widget.setGeometry(400, 0, 400, 450)
        self.login_widget.setStyleSheet("background-color: transparent; border: none;")
        layout = QVBoxLayout(self.login_widget)
        layout.setContentsMargins(50, 50, 50, 50)

        title = QLabel("Login")
        title.setStyleSheet("font-size: 28px; font-weight: bold; color: #333;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        layout.addSpacing(40)

        self.login_user = QLineEdit(placeholderText="Username")
        self.login_pass = QLineEdit(placeholderText="Password")
        self.login_pass.setEchoMode(QLineEdit.EchoMode.Password)

        for le in [self.login_user, self.login_pass]:
            le.setStyleSheet("border: none; border-bottom: 2px solid #ccc; padding: 8px; font-size: 14px;")
            layout.addWidget(le)

        layout.addSpacing(40)
        self.btn_login = QPushButton("LOGIN")
        self.btn_login.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_login.setStyleSheet("""
            QPushButton { background-color: #007acc; color: white; border-radius: 10px; padding: 12px; font-weight: bold;}
            QPushButton:hover { background-color: #005c99; }
        """)
        self.btn_login.clicked.connect(self.handle_login_click)
        layout.addWidget(self.btn_login)
        layout.addStretch()

        btn_switch = QPushButton("New here? Sign Up")
        btn_switch.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn_switch.setStyleSheet("color: #666; border: none; font-weight: bold; background: transparent;")
        btn_switch.clicked.connect(self.animate_to_signup)
        layout.addWidget(btn_switch, alignment=Qt.AlignmentFlag.AlignCenter)

    def setup_overlay(self):
        self.overlay = QFrame(self.container)
        self.overlay.setGeometry(0, 0, 400, 450)
        self.update_overlay_style(left=True)
        layout = QVBoxLayout(self.overlay)
        lbl_logo = QLabel("PneuNet")
        lbl_logo.setStyleSheet(
            "font-size: 40px; font-weight: bold; color: white; background: transparent; border: none;")
        lbl_desc = QLabel("Secure Medical Analysis")
        lbl_desc.setStyleSheet("font-size: 16px; color: #eee; background: transparent; border: none;")
        layout.addStretch()
        layout.addWidget(lbl_logo, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(lbl_desc, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addStretch()
        self.anim = QPropertyAnimation(self.overlay, b"pos")
        self.anim.setDuration(500)
        self.anim.setEasingCurve(QEasingCurve.Type.InOutQuart)

    def update_overlay_style(self, left=True):
        radius = "20px 0px 0px 20px" if left else "0px 20px 20px 0px"
        self.overlay.setStyleSheet(f"""
            QFrame {{
                background-color: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #00d2ff, stop:1 #3a7bd5);
                border-radius: {radius};
                border: none;
            }}
        """)

    def animate_to_signup(self):
        self.anim.setStartValue(QPoint(0, 0))
        self.anim.setEndValue(QPoint(400, 0))
        self.update_overlay_style(left=False)
        self.anim.start()

    def animate_to_login(self):
        self.anim.setStartValue(QPoint(400, 0))
        self.anim.setEndValue(QPoint(0, 0))
        self.update_overlay_style(left=True)
        self.anim.start()

    # --- REAL LOGIC ---

    def _ensure_connection(self):
        if not self.client:
            raise RuntimeError("Client not initialized.")
        if not self.client.is_connected:
            self.client.connect()

    def handle_login_click(self):
        username = self.login_user.text().strip()
        password = self.login_pass.text().strip()

        if not username or not password:
            QMessageBox.warning(self, "Error", "Please enter username and password.")
            return

        self.btn_login.setEnabled(False)
        self.btn_login.setText("Connecting...")

        self.worker = Worker(self._do_login, username, password)
        self.worker.finished.connect(self.on_login_success)
        self.worker.error.connect(self.on_auth_error)
        self.worker.start()

    def _do_login(self, u, p):
        self._ensure_connection()
        return self.client.login(u, p)

    def on_login_success(self, response):
        self.btn_login.setEnabled(True)
        self.btn_login.setText("LOGIN")

        # Check if response is valid (Response type LOGIN_OK checked in client, but double check)
        # client.login returns the dict
        self.home_window = HomeWindow(self.client, username=self.login_user.text())
        self.home_window.show()
        self.close()

    def on_auth_error(self, msg):
        self.btn_login.setEnabled(True)
        self.btn_login.setText("LOGIN")
        self.btn_signup.setEnabled(True)
        self.btn_signup.setText("SIGN UP")
        QMessageBox.warning(self, "Authentication Failed", str(msg))

    def handle_signup_click(self):
        name = self.reg_name.text().strip()
        password = self.reg_pass.text().strip()

        self.btn_signup.setEnabled(False)
        self.btn_signup.setText("Registering...")

        self.worker = Worker(self._do_signup, name, password)
        self.worker.finished.connect(self.on_signup_success)
        self.worker.error.connect(self.on_auth_error)
        self.worker.start()

    def _do_signup(self, u, p):
        self._ensure_connection()
        return self.client.signup(u, p)

    def on_signup_success(self, response):
        self.btn_signup.setEnabled(True)
        self.btn_signup.setText("SIGN UP")
        QMessageBox.information(self, "Success", "Account created! Please login.")
        self.animate_to_login()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    if not Client:
        QMessageBox.critical(None, "Fatal Error", "Could not find 'client.py'. Please check file structure.")
    else:
        window = AuthWindow()
        window.show()
        sys.exit(app.exec())