from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QFileDialog, QTextEdit
from cryptography.fernet import Fernet
import sys, os, hashlib, json
from datetime import datetime

class SecureStorage(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure File Storage System")
        self.resize(500, 400)

        # GUI Elements
        self.log = QTextEdit()
        self.log.setReadOnly(True)

        self.upload_btn = QPushButton("Upload File")
        self.encrypt_btn = QPushButton("Encrypt")
        self.decrypt_btn = QPushButton("Decrypt")
        self.verify_btn = QPushButton("Verify Integrity")

        layout = QVBoxLayout()
        layout.addWidget(self.upload_btn)
        layout.addWidget(self.encrypt_btn)
        layout.addWidget(self.decrypt_btn)
        layout.addWidget(self.verify_btn)
        layout.addWidget(self.log)
        self.setLayout(layout)

        self.upload_btn.clicked.connect(self.upload_file)
        self.encrypt_btn.clicked.connect(self.encrypt_file)
        self.decrypt_btn.clicked.connect(self.decrypt_file)
        self.verify_btn.clicked.connect(self.verify_file)

    def upload_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.file_path = file_path
            self.log.append(f"📁 Selected: {file_path}")

    def encrypt_file(self):
        if not hasattr(self, 'file_path') or not self.file_path:
            self.log.append("⚠️ No file selected.")
            return

        try:
            key = Fernet.generate_key()
            cipher = Fernet(key)

            with open(self.file_path, "rb") as f:
                data = f.read()
                encrypted = cipher.encrypt(data)

            enc_path = self.file_path + ".enc"
            with open(enc_path, "wb") as f:
                f.write(encrypted)

            meta = {
                "original": os.path.basename(self.file_path),
                "timestamp": datetime.now().isoformat(),
                "hash": hashlib.sha256(data).hexdigest(),
                "key": key.decode()
            }

            with open(enc_path + ".meta", "w") as f:
                json.dump(meta, f)

            self.log.append(f"✅ Encrypted and saved: {enc_path}")
        except Exception as e:
            self.log.append(f"❌ Encryption failed: {str(e)}")

    def decrypt_file(self):
        enc_path, _ = QFileDialog.getOpenFileName(self, "Select .enc File")
        if not enc_path:
            return

        try:
            with open(enc_path + ".meta", "r") as f:
                meta = json.load(f)

            key = meta["key"].encode()
            cipher = Fernet(key)

            with open(enc_path, "rb") as f:
                encrypted = f.read()
                decrypted = cipher.decrypt(encrypted)

            out_path = enc_path.replace(".enc", "_decrypted")
            with open(out_path, "wb") as f:
                f.write(decrypted)

            self.log.append(f"🔓 Decrypted and saved: {out_path}")
        except Exception as e:
            self.log.append(f"❌ Decryption failed: {str(e)}")

    def verify_file(self):
        enc_path, _ = QFileDialog.getOpenFileName(self, "Select .enc File")
        if not enc_path:
            return

        try:
            with open(enc_path + ".meta", "r") as f:
                meta = json.load(f)

            key = meta["key"].encode()
            cipher = Fernet(key)

            with open(enc_path, "rb") as f:
                encrypted = f.read()
                decrypted = cipher.decrypt(encrypted)

            current_hash = hashlib.sha256(decrypted).hexdigest()
            if current_hash == meta["hash"]:
                self.log.append("✅ Integrity verified: hash matches.")
            else:
                self.log.append("❌ Integrity check failed: hash mismatch.")
        except Exception as e:
            self.log.append(f"❌ Verification failed: {str(e)}")

# Run the GUI
app = QApplication(sys.argv)
window = SecureStorage()
window.show()
sys.exit(app.exec_())

