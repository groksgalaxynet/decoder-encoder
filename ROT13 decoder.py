import sys
import codecs
import json
import csv
import sqlite3
import base64
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QTextEdit, QPushButton, QLabel, 
                             QFileDialog, QComboBox, QRadioButton, QButtonGroup, QLineEdit)
from PyQt6.QtCore import Qt

# Added for high-level AI security
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    # Fallback or notification could be added here
    pass

class MultiCodecMonitor(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Bot Monitor: Advanced AI Crypto-Suite")
        self.resize(1000, 800)
        self.init_ui()
        self.apply_dark_mode()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Mode Selection
        mode_layout = QHBoxLayout()
        self.mode_group = QButtonGroup(self)
        self.decrypt_radio = QRadioButton("Decrypt Mode (Monitor)")
        self.encrypt_radio = QRadioButton("Encrypt Mode (Craft)")
        self.decrypt_radio.setChecked(True)
        self.mode_group.addButton(self.decrypt_radio)
        self.mode_group.addButton(self.encrypt_radio)
        
        # Expanded Algorithm Selection
        self.codec_selector = QComboBox()
        self.codec_selector.addItems([
            "ROT13", "Base64", "Hexadecimal", 
            "Atbash", "Caesar (Shift 3)", "Vigenère", "AES-256 (Fernet)"
        ])
        self.codec_selector.currentTextChanged.connect(self.toggle_key_input)
        
        mode_layout.addWidget(self.decrypt_radio)
        mode_layout.addWidget(self.encrypt_radio)
        mode_layout.addStretch()
        mode_layout.addWidget(QLabel("Algorithm:"))
        mode_layout.addWidget(self.codec_selector)
        main_layout.addLayout(mode_layout)

        # Key Input (Hidden by default, used for Vigenère/AES)
        self.key_label = QLabel("Secret Key / Password:")
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Enter key for Vigenère or AES...")
        self.key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.key_input.setVisible(False)
        self.key_label.setVisible(False)
        main_layout.addWidget(self.key_label)
        main_layout.addWidget(self.key_input)

        # Input Area
        main_layout.addWidget(QLabel("Input Text:"))
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Paste strings here...")
        self.input_text.textChanged.connect(self.process_data)
        main_layout.addWidget(self.input_text)

        # Action & Export Buttons
        button_layout = QHBoxLayout()
        self.save_json_btn = QPushButton("Save JSON")
        self.save_csv_btn = QPushButton("Save CSV")
        self.save_sql_btn = QPushButton("Save SQLite")
        self.copy_btn = QPushButton("Copy Result")

        self.save_json_btn.clicked.connect(self.save_json)
        self.save_csv_btn.clicked.connect(self.save_csv)
        self.save_sql_btn.clicked.connect(self.save_sqlite)
        self.copy_btn.clicked.connect(self.copy_to_clipboard)

        button_layout.addWidget(self.save_json_btn)
        button_layout.addWidget(self.save_csv_btn)
        button_layout.addWidget(self.save_sql_btn)
        button_layout.addWidget(self.copy_btn)
        main_layout.addLayout(button_layout)

        # Output Area
        main_layout.addWidget(QLabel("Processed Result:"))
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        main_layout.addWidget(self.output_text)

    def apply_dark_mode(self):
        self.setStyleSheet("""
            QMainWindow, QWidget { background-color: #121212; color: #E0E0E0; }
            QTextEdit, QLineEdit { background-color: #1E1E1E; border: 1px solid #333; border-radius: 4px; padding: 10px; font-family: 'Consolas', monospace; color: #00FF41; }
            QPushButton { background-color: #2D2D2D; border: 1px solid #444; padding: 10px; border-radius: 5px; font-weight: bold; }
            QPushButton:hover { background-color: #3D3D3D; border: 1px solid #666; }
            QComboBox { background-color: #2D2D2D; border: 1px solid #444; padding: 5px; color: #E0E0E0; }
            QLabel { font-weight: bold; margin-top: 10px; color: #BB86FC; }
        """)

    def toggle_key_input(self):
        show_key = self.codec_selector.currentText() in ["Vigenère", "AES-256 (Fernet)"]
        self.key_input.setVisible(show_key)
        self.key_label.setVisible(show_key)

    def process_data(self):
        text = self.input_text.toPlainText().strip()
        if not text:
            self.output_text.clear()
            return
        
        algo = self.codec_selector.currentText()
        is_encrypt = self.encrypt_radio.isChecked()
        key = self.key_input.text()

        try:
            if algo == "ROT13":
                result = codecs.encode(text, 'rot_13')
            
            elif algo == "Base64":
                result = base64.b64encode(text.encode()).decode() if is_encrypt else base64.b64decode(text.encode()).decode(errors='replace')
            
            elif algo == "Atbash":
                abc = "abcdefghijklmnopqrstuvwxyz"
                atbash_map = str.maketrans(abc + abc.upper(), abc[::-1] + abc.upper()[::-1])
                result = text.translate(atbash_map)

            elif algo == "Caesar (Shift 3)":
                shift = 3 if is_encrypt else -3
                result = "".join([chr((ord(c) - 65 + shift) % 26 + 65) if c.isupper() else chr((ord(c) - 97 + shift) % 26 + 97) if c.islower() else c for c in text])

            elif algo == "Vigenère":
                if not key: return
                result = self.vigenere_cipher(text, key, is_encrypt)

            elif algo == "AES-256 (Fernet)":
                if not key: return
                result = self.aes_fernet(text, key, is_encrypt)
            
            elif algo == "Hexadecimal":
                result = text.encode().hex(' ') if is_encrypt else bytes.fromhex(text.replace(' ', '')).decode(errors='replace')
            
            self.output_text.setPlainText(result)
        except Exception as e:
            self.output_text.setPlainText(f"[Error]: {str(e)}")

    def vigenere_cipher(self, text, key, encrypt=True):
        res = []
        key = key.lower()
        key_idx = 0
        for char in text:
            if char.isalpha():
                shift = ord(key[key_idx % len(key)]) - 97
                if not encrypt: shift = -shift
                base = 65 if char.isupper() else 97
                res.append(chr((ord(char) - base + shift) % 26 + base))
                key_idx += 1
            else:
                res.append(char)
        return "".join(res)

    def aes_fernet(self, text, password, encrypt=True):
        # Derive a stable 32-byte key from password for Fernet
        salt = b'static_salt_for_bots' # In production, use a dynamic salt
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        f = Fernet(key)
        return f.encrypt(text.encode()).decode() if encrypt else f.decrypt(text.encode()).decode()

    # --- Export Methods ---
    def copy_to_clipboard(self):
        QApplication.clipboard().setText(self.output_text.toPlainText())

    def save_json(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save JSON", "", "JSON Files (*.json)")
        if path:
            with open(path, 'w') as f:
                json.dump({"algo": self.codec_selector.currentText(), "output": self.output_text.toPlainText()}, f, indent=4)

    def save_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save CSV", "", "CSV Files (*.csv)")
        if path:
            with open(path, 'w', newline='') as f:
                csv.writer(f).writerow([self.codec_selector.currentText(), self.output_text.toPlainText()])

    def save_sqlite(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save SQLite", "", "SQLite Files (*.db)")
        if path:
            conn = sqlite3.connect(path)
            conn.execute("CREATE TABLE IF NOT EXISTS logs (algo TEXT, data TEXT)")
            conn.execute("INSERT INTO logs VALUES (?, ?)", (self.codec_selector.currentText(), self.output_text.toPlainText()))
            conn.commit()
            conn.close()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MultiCodecMonitor()
    window.show()
    sys.exit(app.exec())


