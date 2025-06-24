import os
import sys
import json
import random
import string
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton,
    QMessageBox, QListWidget, QHBoxLayout, QInputDialog, QComboBox, QTextEdit
)
from PyQt6.QtGui import QGuiApplication
from PyQt6.QtCore import Qt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import base64

VAULT_FILE = "vault.json"

# --- Crypto Manager ---
class CryptoManager:
    def __init__(self, password: str):
        self.password = password.encode()
        self.salt = b"static_salt_for_demo"  # Üretim için dosyada rastgele saklanmalı
        self.key = self.derive_key()

    def derive_key(self):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=390000,
            backend=default_backend()
        )
        return kdf.derive(self.password)

    def encrypt(self, data: bytes) -> bytes:
        aesgcm = AESGCM(self.key)
        nonce = os.urandom(12)
        encrypted = aesgcm.encrypt(nonce, data, None)
        return base64.b64encode(nonce + encrypted)

    def decrypt(self, data: bytes) -> bytes:
        aesgcm = AESGCM(self.key)
        decoded = base64.b64decode(data)
        nonce = decoded[:12]
        ciphertext = decoded[12:]
        return aesgcm.decrypt(nonce, ciphertext, None)

# --- Password Generator ---
def generate_password(length=16):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

# --- Şifre Giriş Widget (Gizle / Göster) ---
class PasswordInputWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QHBoxLayout()
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.toggle_button = QPushButton("Göster")
        self.toggle_button.setCheckable(True)
        self.toggle_button.toggled.connect(self.toggle_password)
        self.layout.addWidget(self.password_edit)
        self.layout.addWidget(self.toggle_button)
        self.setLayout(self.layout)

    def toggle_password(self, checked):
        if checked:
            self.password_edit.setEchoMode(QLineEdit.EchoMode.Normal)
            self.toggle_button.setText("Gizle")
        else:
            self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
            self.toggle_button.setText("Göster")

    def text(self):
        return self.password_edit.text()

    def setText(self, text):
        self.password_edit.setText(text)

# --- Hesap Kurulum Penceresi ---
class AccountSetupWindow(QWidget):
    def __init__(self, on_setup_complete):
        super().__init__()
        self.on_setup_complete = on_setup_complete
        self.setWindowTitle("SafeBox - Hesap Oluştur")
        self.setGeometry(300, 300, 400, 350)

        layout = QVBoxLayout()

        layout.addWidget(QLabel("Lütfen ilk hesabınızı oluşturun:"))

        self.account_name_input = QLineEdit()
        self.account_name_input.setPlaceholderText("Hesap Adı (ör. Gmail, Facebook)")
        layout.addWidget(self.account_name_input)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Kullanıcı Adı / Email")
        layout.addWidget(self.username_input)

        layout.addWidget(QLabel("Ana Parola:"))
        self.master_password_input = PasswordInputWidget()
        layout.addWidget(self.master_password_input)

        layout.addWidget(QLabel("Ana Parola (Tekrar):"))
        self.confirm_password_input = PasswordInputWidget()
        layout.addWidget(self.confirm_password_input)

        self.create_button = QPushButton("Hesap Oluştur")
        self.create_button.clicked.connect(self.create_account)
        layout.addWidget(self.create_button)

        self.setLayout(layout)

    def create_account(self):
        account_name = self.account_name_input.text().strip()
        username = self.username_input.text().strip()
        master_pwd = self.master_password_input.text()
        confirm_pwd = self.confirm_password_input.text()

        if not (account_name and username and master_pwd and confirm_pwd):
            QMessageBox.warning(self, "Uyarı", "Lütfen tüm alanları doldurun.")
            return
        if master_pwd != confirm_pwd:
            QMessageBox.warning(self, "Uyarı", "Ana parola tekrarları eşleşmiyor.")
            return

        self.on_setup_complete(account_name, username, master_pwd)
        self.close()

# --- Şifre Kasası Ana Pencere ---
class PasswordVaultWindow(QWidget):
    def __init__(self, crypto_manager):
        super().__init__()
        self.crypto = crypto_manager
        self.setWindowTitle("SafeBox - Şifre Kasası")
        self.setGeometry(350, 350, 600, 600)

        self.layout = QVBoxLayout()

        # Kategori Seçici
        self.category_combo = QComboBox()
        self.category_combo.addItem("Tümü")
        self.category_combo.currentTextChanged.connect(self.filter_accounts)
        self.layout.addWidget(self.category_combo)

        # Hesap Listesi
        self.list_widget = QListWidget()
        self.layout.addWidget(self.list_widget)

        # Butonlar
        btn_layout = QHBoxLayout()
        self.add_button = QPushButton("Yeni Hesap Ekle")
        self.delete_button = QPushButton("Seçili Hesabı Sil")
        btn_layout.addWidget(self.add_button)
        btn_layout.addWidget(self.delete_button)
        self.layout.addLayout(btn_layout)

        self.setLayout(self.layout)

        self.add_button.clicked.connect(self.add_account)
        self.delete_button.clicked.connect(self.delete_account)
        self.list_widget.itemDoubleClicked.connect(self.show_password)

        self.accounts = {}
        self.categories = set()
        self.load_accounts()

    def load_accounts(self):
        if not os.path.exists(VAULT_FILE):
            self.accounts = {}
            return
        try:
            with open(VAULT_FILE, "rb") as f:
                decrypted_data = self.crypto.decrypt(f.read())
                self.accounts = json.loads(decrypted_data.decode())
            self.categories = set()
            for v in self.accounts.values():
                cat = v.get("category", "Genel")
                self.categories.add(cat)
            self.update_category_combo()
            self.update_list()
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Hesaplar yüklenemedi: {str(e)}")
            self.accounts = {}

    def update_category_combo(self):
        self.category_combo.blockSignals(True)
        self.category_combo.clear()
        self.category_combo.addItem("Tümü")
        for cat in sorted(self.categories):
            self.category_combo.addItem(cat)
        self.category_combo.blockSignals(False)

    def update_list(self):
        self.list_widget.clear()
        selected_cat = self.category_combo.currentText()
        for title, info in self.accounts.items():
            cat = info.get("category", "Genel")
            if selected_cat == "Tümü" or cat == selected_cat:
                self.list_widget.addItem(title)

    def filter_accounts(self, category):
        self.update_list()

    def add_account(self):
        # Basit form ile tüm alanlar alınacak
        title, ok = QInputDialog.getText(self, "Yeni Hesap", "Hesap Adı:")
        if not ok or not title.strip():
            return
        username, ok_user = QInputDialog.getText(self, "Yeni Hesap", "Kullanıcı Adı / Email:")
        if not ok_user or not username.strip():
            return

        # Şifre oluştur ya da elle gir
        pwd_choice = QMessageBox.question(
            self, "Şifre Seçimi",
            "Şifre otomatik oluşturulsun mu?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if pwd_choice == QMessageBox.StandardButton.Yes:
            password = generate_password()
            QMessageBox.information(self, "Oluşturulan Şifre", f"Oluşturulan şifre:\n{password}")
        else:
            password, ok_pwd = QInputDialog.getText(self, "Yeni Hesap", "Şifre:", QLineEdit.EchoMode.Password)
            if not ok_pwd or not password:
                return

        category, ok_cat = QInputDialog.getText(self, "Yeni Hesap", "Kategori (örnek: İş, Kişisel, Finans):")
        if not ok_cat or not category.strip():
            category = "Genel"

        url, ok_url = QInputDialog.getText(self, "Yeni Hesap", "URL (isteğe bağlı):")
        if not ok_url:
            url = ""

        notes_dialog = QTextEdit()
        notes_dialog.setPlaceholderText("Notlar, güvenlik soruları vb. ekleyebilirsiniz.")
        notes_dialog.resize(400, 150)
        notes_dialog.show()
        ret = QMessageBox.question(self, "Not Ekle", "Not eklemek ister misiniz?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if ret == QMessageBox.StandardButton.Yes:
            notes, ok_notes = QInputDialog.getMultiLineText(self, "Notlar", "Notlarınızı yazın:")
            if not ok_notes:
                notes = ""
        else:
            notes = ""

        self.accounts[title.strip()] = {
            "user": username.strip(),
            "password": password,
            "category": category.strip(),
            "url": url.strip(),
            "notes": notes
        }
        self.categories.add(category.strip())
        self.save_accounts()
        self.update_category_combo()
        self.update_list()

    def delete_account(self):
        selected_items = self.list_widget.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Uyarı", "Silmek için bir hesap seçin.")
            return
        for item in selected_items:
            key = item.text()
            if key in self.accounts:
                del self.accounts[key]
        self.save_accounts()
        self.update_category_combo()
        self.update_list()

    def show_password(self, item):
        ok = False
        for _ in range(3):
            master_pwd, ok_pressed = QInputDialog.getText(
                self, "Parola Doğrulama", "Ana parolayı tekrar girin:", QLineEdit.EchoMode.Password
            )
            if not ok_pressed:
                return
            try:
                crypto_temp = CryptoManager(master_pwd)
                with open(VAULT_FILE, "rb") as f:
                    crypto_temp.decrypt(f.read())
                ok = True
                break
            except Exception:
                QMessageBox.warning(self, "Hata", "Yanlış ana parola, tekrar deneyin.")
        if not ok:
            QMessageBox.critical(self, "Hata", "3 yanlış deneme sonrası işlem iptal edildi.")
            return

        title = item.text()
        entry = self.accounts.get(title)
        if entry:
            # Bilgileri gösterme, kopyala butonu dahil
            msg = QMessageBox(self)
            msg.setWindowTitle(f"{title} Hesap Bilgileri")
            info_text = (
                f"Kullanıcı Adı: {entry.get('user', '')}\n"
                f"Şifre: {entry.get('password', '')}\n"
                f"Kategori: {entry.get('category', '')}\n"
                f"URL: {entry.get('url', '')}\n"
                f"Notlar: {entry.get('notes', '')}\n"
            )
            msg.setText(info_text)
            copy_btn = msg.addButton("Şifreyi Kopyala", QMessageBox.ButtonRole.ActionRole)
            msg.addButton(QMessageBox.StandardButton.Ok)
            msg.exec()

            if msg.clickedButton() == copy_btn:
                QGuiApplication.clipboard().setText(entry.get('password', ''))
                QMessageBox.information(self, "Bilgi", "Şifre panoya kopyalandı.")

    def save_accounts(self):
        try:
            data = json.dumps(self.accounts).encode()
            encrypted = self.crypto.encrypt(data)
            with open(VAULT_FILE, "wb") as f:
                f.write(encrypted)
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Hesaplar kaydedilemedi: {str(e)}")

# --- Ana Parola Girişi ve Setup ---
class PasswordManager(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SafeBox - Ana Parola")
        self.setGeometry(300, 300, 350, 150)

        self.setup_mode = not os.path.exists(VAULT_FILE) or os.path.getsize(VAULT_FILE) == 0

        if self.setup_mode:
            self.account_setup = AccountSetupWindow(self.on_setup_complete)
            self.account_setup.show()
            self.close()
        else:
            self.init_login_ui()

    def init_login_ui(self):
        layout = QVBoxLayout()

        self.label = QLabel("Ana Parolayı Girin:")
        self.password_input = PasswordInputWidget()
        self.button = QPushButton("Giriş")
        self.button.clicked.connect(self.handle_password)

        layout.addWidget(self.label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.button)

        self.setLayout(layout)
        self.show()

    def on_setup_complete(self, account_name, username, master_pwd):
        crypto = CryptoManager(master_pwd)

        accounts = {
            account_name: {
                "user": username,
                "password": "",
                "category": "Genel",
                "url": "",
                "notes": ""
            }
        }
        with open(VAULT_FILE, "wb") as f:
            encrypted = crypto.encrypt(json.dumps(accounts).encode())
            f.write(encrypted)

        QMessageBox.information(None, "Başarılı", "Hesap oluşturuldu, uygulama açılıyor.")
        self.open_vault_window(crypto)

    def handle_password(self):
        password = self.password_input.text()
        if not password:
            QMessageBox.warning(self, "Uyarı", "Parola boş olamaz.")
            return
        crypto = CryptoManager(password)
        try:
            with open(VAULT_FILE, "rb") as f:
                _ = crypto.decrypt(f.read())
            QMessageBox.information(self, "Başarılı", "Ana parola doğru! Devam edebilirsiniz.")
            self.open_vault_window(crypto)
        except Exception:
            QMessageBox.critical(self, "Hata", "Ana parola yanlış!")

    def open_vault_window(self, crypto):
        self.hide()
        self.vault_window = PasswordVaultWindow(crypto)
        self.vault_window.show()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PasswordManager()
    sys.exit(app.exec())
