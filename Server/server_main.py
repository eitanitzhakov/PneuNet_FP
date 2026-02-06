import os
import sys

# הוספת התיקייה הנוכחית ל-path כדי לאפשר טעינת מודולים
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

from server import Server

if __name__ == "__main__":
    import cipher

    print("Loading cipher from:", cipher.__file__)
    print("[INIT] Starting PneuNet Server...")

    # הגדרות הרצה - אפשר לשנות כאן את הנתיב למשקלים (weights)
    # אם אין לך את קובץ המשקלים, השרת יעלה אך ללא יכולת חיזוי (ידפיס Warning)
    weights_path = r"C:\Users\eitan\PycharmProjects\PneuNet_FP\Server\best_ft.pth"

    try:
        # יצירת מופע של השרת
        server = Server(
            host="0.0.0.0",
            port=8080,
            weights_path=weights_path
        )

        # הפעלת השרת
        server.start()

    except KeyboardInterrupt:
        print("\n[STOP] Server stopping requested by user.")
    except Exception as e:
        print(f"[ERROR] Server failed to start: {e}")