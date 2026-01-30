import sys
import codecs
import json
import csv
import sqlite3
import base64
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QTextEdit, QPushButton, QLabel, 
                             QFileDialog, QComboBox, QRadioButton, QButtonGroup)
from PyQt6.QtCore import Qt

class MultiCodecMonitor(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Bot Monitor: Multi-Codec Decoder/Encoder")
        self.resize(900, 700)
        self.init_ui()
        self.apply_dark_mode()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Mode Selection (Encrypt vs Decrypt)
        mode_layout = QHBoxLayout()
        self.mode_group = QButtonGroup(self)
        self.decrypt_radio = QRadioButton("Decrypt Mode (Monitor)")
        self.encrypt_radio = QRadioButton("Encrypt Mode (Craft)")
        self.decrypt_radio.setChecked(True)
        self.mode_group.addButton(self.decrypt_radio)
        self.mode_group.addButton(self.encrypt_radio)
        
        # Codec Selection
        self.codec_selector = QComboBox()
        self.codec_selector.addItems(["ROT13", "Base64", "Hexadecimal"])
        
        mode_layout.addWidget(self.decrypt_radio)
        mode_layout.addWidget(self.encrypt_radio)
        mode_layout.addStretch()
        mode_layout.addWidget(QLabel("Algorithm:"))
        mode_layout.addWidget(self.codec_selector)
        main_layout.addLayout(mode_layout)

        # Input
        main_layout.addWidget(QLabel("Input Text:"))
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Paste encoded strings here...")
        self.input_text.textChanged.connect(self.process_data)
        main_layout.addWidget(self.input_text)

        # Action & Export Buttons
        button_layout = QHBoxLayout()
        
        # Fixed Button Connections
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

        # Output
        main_layout.addWidget(QLabel("Processed Result:"))
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        main_layout.addWidget(self.output_text)

    def apply_dark_mode(self):
        self.setStyleSheet("""
            QMainWindow, QWidget { background-color: #121212; color: #E0E0E0; }
            QTextEdit { background-color: #1E1E1E; border: 1px solid #333; border-radius: 4px; padding: 10px; font-family: 'Consolas', 'Monaco', monospace; font-size: 13px; }
            QPushButton { background-color: #2D2D2D; border: 1px solid #444; padding: 10px; border-radius: 5px; font-weight: bold; }
            QPushButton:hover { background-color: #3D3D3D; border: 1px solid #666; }
            QComboBox { background-color: #2D2D2D; border: 1px solid #444; padding: 5px; color: #E0E0E0; }
            QRadioButton { spacing: 8px; }
            QLabel { font-weight: bold; margin-top: 10px; color: #BB86FC; }
        """)

    def process_data(self):
        text = self.input_text.toPlainText().strip()
        if not text:
            self.output_text.clear()
            return
        
        algo = self.codec_selector.currentText()
        is_encrypt = self.encrypt_radio.isChecked()

        try:
            if algo == "ROT13":
                result = codecs.encode(text, 'rot_13')
            
            elif algo == "Base64":
                if is_encrypt:
                    result = base64.b64encode(text.encode()).decode()
                else:
                    # Clean common base64 issues
                    result = base64.b64decode(text.encode()).decode(errors='replace')
            
            elif algo == "Hexadecimal":
                if is_encrypt:
                    result = text.encode().hex(' ')
                else:
                    clean_hex = "".join(text.replace(' ', '').replace('\n', ''))
                    result = bytes.fromhex(clean_hex).decode(errors='replace')
            
            self.output_text.setPlainText(result)
        except Exception as e:
            self.output_text.setPlainText(f"[Error processing {algo}]: {str(e)}")

    def copy_to_clipboard(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.output_text.toPlainText())

    def save_json(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save JSON", "", "JSON Files (*.json)")
        if path:
            data = {"input": self.input_text.toPlainText(), "output": self.output_text.toPlainText(), "codec": self.codec_selector.currentText()}
            with open(path, 'w') as f:
                json.dump(data, f, indent=4)

    def save_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save CSV", "", "CSV Files (*.csv)")
        if path:
            with open(path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["Codec", "Raw", "Processed"])
                writer.writerow([self.codec_selector.currentText(), self.input_text.toPlainText(), self.output_text.toPlainText()])

    def save_sqlite(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save SQLite", "", "SQLite Files (*.sqlite *.db)")
        if path:
            conn = sqlite3.connect(path)
            conn.execute("CREATE TABLE IF NOT EXISTS bot_logs (id INTEGER PRIMARY KEY, codec TEXT, raw TEXT, processed TEXT)")
            conn.execute("INSERT INTO bot_logs (codec, raw, processed) VALUES (?, ?, ?)", 
                         (self.codec_selector.currentText(), self.input_text.toPlainText(), self.output_text.toPlainText()))
            conn.commit()
            conn.close()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MultiCodecMonitor()
    window.show()
    sys.exit(app.exec())