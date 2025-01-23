import streamlit as st
import sqlite3
import bcrypt

# Membuat koneksi ke database SQLite
conn = sqlite3.connect("users.db")
cursor = conn.cursor()

# Membuat tabel user jika belum ada
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL
)
""")
conn.commit()

# Fungsi untuk hashing password
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Fungsi untuk memeriksa password
def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

# Fungsi untuk menambahkan pengguna baru
def register_user(username, email, password, role="user"):
    hashed_password = hash_password(password)
    try:
        cursor.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)", 
                       (username, email, hashed_password, role))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

# Fungsi untuk login
def login_user(username, password):
    cursor.execute("SELECT password, role FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    if result:
        stored_password, role = result
        if verify_password(password, stored_password.encode('utf-8')):
            return role
    return None

# Fungsi untuk mendapatkan email pengguna
def get_user_email(username):
    cursor.execute("SELECT email FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    if result:
        return result[0]
    return None

# Fungsi dashboard dinamis
def show_dashboard(role):
    st.subheader(f"Dashboard {role.capitalize()}")
    if role == "admin":
        st.write("Ini adalah dashboard admin. Anda bisa mengelola pengguna atau melihat statistik.")
        st.write("Contoh fitur admin:")
        st.write("- Tambah/Hapus pengguna")
        st.write("- Lihat laporan")
    else:
        st.write("Ini adalah dashboard user. Selamat menikmati layanan kami!")
        st.write("Contoh fitur user:")
        st.write("- Profil pengguna")
        st.write("- Lihat aktivitas Anda")

# Halaman login, registrasi, dan logout
st.title("Sistem Login dengan Fitur Lengkap")

# Sesi untuk pengguna
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.role = None

menu = st.sidebar.selectbox("Menu", ["Login", "Registrasi", "Logout"] if st.session_state.logged_in else ["Login", "Registrasi"])

if menu == "Login":
    st.subheader("Login")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        login_button = st.form_submit_button("Login")
    
    if login_button:
        role = login_user(username, password)
        if role:
            st.success(f"Selamat datang, {username}!")
            st.session_state.logged_in = True
            st.session_state.username = username
            st.session_state.role = role
        else:
            st.error("Username atau password salah!")

elif menu == "Registrasi":
    st.subheader("Registrasi")
    with st.form("register_form"):
        new_username = st.text_input("Buat Username")
        new_email = st.text_input("Masukkan Email")
        new_password = st.text_input("Buat Password", type="password")
        role = st.selectbox("Pilih Role", ["user", "admin"])
        register_button = st.form_submit_button("Registrasi")
    
    if register_button:
        if register_user(new_username, new_email, new_password, role):
            st.success("Registrasi berhasil! Silakan login.")
        else:
            st.error("Username sudah digunakan. Coba username lain.")

elif menu == "Logout":
    if st.session_state.logged_in:
        st.session_state.logged_in = False
        st.session_state.username = None
        st.session_state.role = None
        st.success("Anda berhasil logout.")

# Tampilkan dashboard jika sudah login
if st.session_state.logged_in:
    st.sidebar.write(f"👤 **{st.session_state.username}** ({st.session_state.role.capitalize()})")
    show_dashboard(st.session_state.role)
