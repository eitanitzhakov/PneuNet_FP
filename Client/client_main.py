import sys
import os

# הוספת התיקייה הנוכחית ל-sys.path כדי שהמערכת תזהה את המודולים (client, GUI)
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

from PySide6.QtWidgets import QApplication
# ייבוא חלון ההתחברות מתוך תיקיית ה-GUI
from gui import AuthWindow

if __name__ == "__main__":
    # יצירת האפליקציה הגרפית
    app = QApplication(sys.argv)

    # יצירת החלון הראשי (מסך התחברות)
    # כברירת מחדל הוא ינסה להתחבר ל-127.0.0.1:8080
    window = AuthWindow()
    window.show()

    # הרצת הלולאה הראשית של הממשק
    sys.exit(app.exec())