import sys
import sqlite3
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QPushButton, QLineEdit, QVBoxLayout, QWidget, QFileDialog, QMessageBox, QInputDialog, QTextEdit, QListWidget

class User:
    def __init__(self, username, password, is_admin):
        self.username = username
        self.password = password
        self.is_admin = is_admin

class UserManager:
    def __init__(self):
        self.users = []

    def add_user(self, user):
        self.users.append(user)

class Record:
    def __init__(self, id, name, picture_path, contact_number):
        self.id = id
        self.name = name
        self.picture_path = picture_path
        self.contact_number = contact_number

class RecordManager:
    def __init__(self):
        self.records = []

    def add_record(self, record):
        self.records.append(record)

class AppWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.conn = sqlite3.connect("record_management.db")
        self.cursor = self.conn.cursor()

        self.create_tables()
        self.user_manager = UserManager()
        self.record_manager = RecordManager()
        self.load_users()

        self.current_user = None

        self.setWindowTitle("Record Management System")
        self.setGeometry(100, 100, 800, 600)

        self.login_layout = QVBoxLayout()
        self.login_input = QLineEdit()
        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.login)
        self.login_layout.addWidget(QLabel("Username:"))
        self.login_layout.addWidget(self.login_input)
        self.login_layout.addWidget(self.login_button)

        container = QWidget()
        container.setLayout(self.login_layout)
        self.setCentralWidget(container)

        self.picture_path = ""

        self.id_input = QLineEdit()
        self.name_input = QLineEdit()
        self.contact_input = QLineEdit()

    def create_tables(self):
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT,
                            password TEXT,
                            is_admin BOOLEAN)''')

        self.cursor.execute('''CREATE TABLE IF NOT EXISTS records (
                            id INTEGER PRIMARY KEY,
                            user_id INTEGER,
                            name TEXT,
                            picture_path TEXT,
                            contact_number TEXT)''')
        self.conn.commit()

    def load_users(self):
        self.cursor.execute("SELECT * FROM users")
        users_data = self.cursor.fetchall()

        admin_exists = False

        for user_data in users_data:
            user = User(user_data[1], user_data[2], user_data[3])
            self.user_manager.add_user(user)
            if user.username == "admin":
                admin_exists = True

        if not admin_exists:
            self.create_default_admin()

    def create_default_admin(self):
        default_admin = User("admin", "admin", True)
        self.cursor.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
                            (default_admin.username, default_admin.password, default_admin.is_admin))
        self.conn.commit()
        self.user_manager.add_user(default_admin)

    def find_user(self, username, password):
        self.cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user_data = self.cursor.fetchone()

        if user_data:
            user = User(user_data[1], user_data[2], user_data[3])
            return user
        return None

    def login(self):
        username = self.login_input.text()
        password, ok = QInputDialog.getText(self, "Password", f"Enter password for {username}:", QLineEdit.Password)
        if ok and password:
            user = self.find_user(username, password)
            if user:
                self.current_user = user
                self.current_user.id = self.get_user_id(username)
                self.show_main_window()
            else:
                QMessageBox.warning(self, "Login Failed", "Invalid username or password.")

    def get_user_id(self, username):
        self.cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        user_id = self.cursor.fetchone()
        if user_id:
            return user_id[0]
        return None

    def show_main_window(self):
        if self.current_user.is_admin:
            self.create_admin_widgets()
        else:
            self.create_user_widgets()

    def create_admin_widgets(self):
        admin_layout = QVBoxLayout()
        admin_layout.addWidget(QLabel(f"Welcome, {self.current_user.username} (Admin)!"))
        admin_layout.addLayout(self.create_input_fields())
        admin_layout.addWidget(self.create_picture_button())
        admin_layout.addWidget(self.create_register_button())
        admin_layout.addWidget(self.create_report_button())
        admin_layout.addWidget(self.create_records_text())
        admin_layout.addWidget(self.create_records_list())
        admin_container = QWidget()
        admin_container.setLayout(admin_layout)
        self.setCentralWidget(admin_container)

    def create_user_widgets(self):
        user_layout = QVBoxLayout()
        user_layout.addWidget(QLabel(f"Welcome, {self.current_user.username}!"))
        user_layout.addLayout(self.create_input_fields())
        user_layout.addWidget(self.create_picture_button())
        user_layout.addWidget(self.create_register_button())
        user_layout.addWidget(self.create_records_text())
        user_container = QWidget()
        user_container.setLayout(user_layout)
        self.setCentralWidget(user_container)

    def upload_picture(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Picture", "", "Images (*.png *.jpg *.jpeg)", options=options)

        if file_path:
            self.picture_path = file_path

    def create_input_fields(self):
        input_layout = QVBoxLayout()
        input_layout.addWidget(QLabel("ID:"))
        input_layout.addWidget(self.id_input)
        input_layout.addWidget(QLabel("Name:"))
        input_layout.addWidget(self.name_input)
        input_layout.addWidget(QLabel("Contact Number:"))
        input_layout.addWidget(self.contact_input)
        return input_layout

    def create_picture_button(self):
        button = QPushButton("Upload Picture")
        button.clicked.connect(self.upload_picture)
        return button

    def create_register_button(self):
        self.register_button = QPushButton("Register")
        self.register_button.clicked.connect(self.register_record)
        return self.register_button

    def create_report_button(self):
        self.report_button = QPushButton("Generate Report")
        self.report_button.clicked.connect(self.generate_report)
        return self.report_button

    def create_records_text(self):
        self.records_text = QTextEdit()
        self.records_text.setReadOnly(True)
        return self.records_text

    def create_records_list(self):
        self.records_list = QListWidget()
        self.records_list.itemClicked.connect(self.edit_selected_record)
        return self.records_list

    def edit_selected_record(self, item):
        index = self.records_list.row(item)
        record = self.record_manager.records[index]
        self.id_input.setText(str(record.id))
        self.name_input.setText(record.name)
        self.contact_input.setText(record.contact_number)
        self.picture_path = record.picture_path
        self.update_input_fields(record.id, record.name, record.picture_path, record.contact_number)
        self.register_button.setText("Update")
        self.register_button.clicked.disconnect()
        self.register_button.clicked.connect(lambda: self.update_record(index))

    def register_record(self):
        id_value = self.id_input.text()
        name = self.name_input.text()
        contact_number = self.contact_input.text()

        if id_value and name and self.picture_path:
            record = Record(None, name, self.picture_path, contact_number)
            self.cursor.execute("INSERT INTO records (user_id, name, picture_path, contact_number) VALUES (?, ?, ?, ?)",
                                (self.current_user.id, record.name, record.picture_path, record.contact_number))
            self.conn.commit()
            record.id = self.cursor.lastrowid
            self.record_manager.add_record(record)
            self.update_records_text()
            self.update_records_list()
            self.clear_input_fields()

    def update_record(self, index):
        id_value = self.id_input.text()
        name = self.name_input.text()
        contact_number = self.contact_input.text()

        if id_value and name and self.picture_path:
            record = self.record_manager.records[index]
            self.cursor.execute("UPDATE records SET name = ?, picture_path = ?, contact_number = ? WHERE id = ?",
                                (name, self.picture_path, contact_number, record.id))
            self.conn.commit()
            record.name = name
            record.picture_path = self.picture_path
            record.contact_number = contact_number
            self.update_records_text()
            self.update_records_list()
            self.clear_input_fields()

    def generate_report(self):
        report = "Records Report:\n\n"
        for record in self.record_manager.records:
            report += f"ID: {record.id}\n"
            report += f"Name: {record.name}\n"
            report += f"Contact Number: {record.contact_number}\n"
            report += f"Picture Path: {record.picture_path}\n\n"

        self.records_text.setPlainText(report)

    def update_records_text(self):
        self.generate_report()

    def update_records_list(self):
        self.records_list.clear()
        for record in self.record_manager.records:
            self.records_list.addItem(str(record.id) + ": " + record.name)

    def update_input_fields(self, id, name, picture_path, contact_number):
        self.id_input.setText(str(id))
        self.name_input.setText(name)
        self.picture_path = picture_path
        self.contact_input.setText(contact_number)

    def clear_input_fields(self):
        self.id_input.clear()
        self.name_input.clear()
        self.contact_input.clear()
        self.picture_path = ""
        self.register_button.setText("Register")
        self.register_button.clicked.disconnect()
        self.register_button.clicked.connect(self.register_record)

def main():
    app = QApplication(sys.argv)
    window = AppWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
