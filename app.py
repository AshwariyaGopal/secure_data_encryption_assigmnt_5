import streamlit as st  # type: ignore
from cryptography.fernet import Fernet  # type: ignore
import hashlib
import base64
import json
import os
import time
import secrets

# Data file path
DATA_FILE = "data.json"

# Load existing data
if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as f:
        stored_data = json.load(f)
else:
    stored_data = {}

# Session state defaults
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = ""
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = None


#  Hashing and Encryption Utils

def hash_passkey(passkey: str, salt: str = None) -> str:
    if not salt:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt.encode(), 100000)
    return f"{salt}${base64.urlsafe_b64encode(key).decode()}"

def verify_passkey(stored_hash: str, input_passkey: str) -> bool:
    try:
        salt, hashed = stored_hash.split('$')
        new_hash = hash_passkey(input_passkey, salt)
        return new_hash == stored_hash
    except Exception:
        return False

def derive_key(passkey: str) -> bytes:
    hashed = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hashed)

def encrypt_text(text: str, passkey: str) -> str:
    key = derive_key(passkey)
    return Fernet(key).encrypt(text.encode()).decode()

def decrypt_text(encrypted_text: str, passkey: str) -> str or None:  # type: ignore
    try:
        key = derive_key(passkey)
        return Fernet(key).decrypt(encrypted_text.encode()).decode()
    except:
        return None

def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump(stored_data, f)



# Pages


def home_page():
    st.title("🔐 Secure Data Encryption System")

    st.markdown(
        """
        <div style="text-align: center; padding: 10px;">
            <p style="font-size: 18px; margin-top: 10px;">
                <b>Welcome!</b><br><br>
                👉 <b>New here?</b> Please <span style="color: #ff7f0e;">Register</span> first.<br>
                👉 <b>Already a member?</b> Please <span style="color: #2ca02c;">Login</span> to continue.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.write("---")

    col1, col2 = st.columns(2)

    with col1:
        if st.button("🔑 Login"):
            st.session_state.page = "login"

    with col2:
        if st.button("📝 Register"):
            st.session_state.page = "register"

    st.write("")
    st.info("📢 Tip: First register yourself if you are new here!")

def register_page():
    st.header("📝 Register New User")
    username = st.text_input("Choose a username")
    passkey = st.text_input("Choose a passkey", type="password")

    if st.button("Register"):
        if username and passkey:
            if username in stored_data:
                st.error("Username already exists. Please login instead.")
            else:
                encrypted_dummy = encrypt_text("Welcome!", passkey)
                stored_data[username] = {
                    "encrypted_text": encrypted_dummy,
                    "passkey": hash_passkey(passkey)
                }
                save_data()
                st.success("Registration successful! Now login.")
                st.session_state.page = "login"
        else:
            st.error("Both fields are required.")

    if st.button("⬅ Back to Home"):
        st.session_state.page = "home"

def login_page():
    st.header("🔐 Login")

    if st.session_state.lockout_time:
        remaining = st.session_state.lockout_time - time.time()
        if remaining > 0:
            st.warning(f"⏳ Too many failed attempts. Please wait {int(remaining)} seconds.")
            st.stop()
        else:
            st.session_state.lockout_time = None
            st.session_state.failed_attempts = 0

    username = st.text_input("Username")
    passkey = st.text_input("Passkey", type="password")

    if st.button("Login"):
        if username in stored_data:
            if verify_passkey(stored_data[username]["passkey"], passkey):
                st.success("Login successful!")
                st.session_state.logged_in = True
                st.session_state.username = username
                st.session_state.failed_attempts = 0
                st.session_state.page = "dashboard"
            else:
                st.session_state.failed_attempts += 1
                st.error(f"Incorrect passkey. Attempts {st.session_state.failed_attempts}/3")
        else:
            st.session_state.failed_attempts += 1
            st.error(f"Username not found. Attempts {st.session_state.failed_attempts}/3")

        if st.session_state.failed_attempts >= 3:
            st.session_state.lockout_time = time.time() + 30  # 30 second lockout
            st.error("🚫 Too many failed attempts. Wait for 30 seconds.")

    if st.button("⬅ Back to Home"):
        st.session_state.page = "home"

def dashboard_page():
    st.header(f"👋 Welcome, {st.session_state.username}!")
    st.subheader("Choose an action:")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Insert New Data"):
            st.session_state.page = "insert"
    with col2:
        if st.button("Retrieve My Data"):
            st.session_state.page = "retrieve"

    if st.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.session_state.failed_attempts = 0
        st.session_state.lockout_time = None
        st.session_state.page = "home"

def insert_page():
    st.header("📥 Insert New Secret Data")
    secret = st.text_area("Enter your secret message")
    passkey = st.text_input("Enter your passkey", type="password")

    if st.button("Save Secret"):
        if passkey:
            if verify_passkey(stored_data[st.session_state.username]["passkey"], passkey):
                encrypted = encrypt_text(secret, passkey)
                stored_data[st.session_state.username]["encrypted_text"] = encrypted
                save_data()
                st.success("Secret updated successfully!")
            else:
                st.error("Wrong passkey.")
        else:
            st.error("Passkey is required.")

    if st.button("⬅ Back to Dashboard"):
        st.session_state.page = "dashboard"

def retrieve_page():
    st.header("🔓 Retrieve Your Secret Data")
    passkey = st.text_input("Enter your passkey", type="password")

    if st.button("Retrieve Secret"):
        if passkey:
            if verify_passkey(stored_data[st.session_state.username]["passkey"], passkey):
                decrypted = decrypt_text(stored_data[st.session_state.username]["encrypted_text"], passkey)
                st.success("Decryption Successful!")
                st.write(f"Your Secret: `{decrypted}`")
            else:
                st.error("Incorrect passkey.")
        else:
            st.error("Passkey is required.")

    if st.button("⬅ Back to Dashboard"):
        st.session_state.page = "dashboard"


# Page Router


if "page" not in st.session_state:
    st.session_state.page = "home"

if st.session_state.page == "home":
    home_page()
elif st.session_state.page == "register":
    register_page()
elif st.session_state.page == "login":
    login_page()
elif st.session_state.page == "dashboard":
    if st.session_state.logged_in:
        dashboard_page()
    else:
        st.session_state.page = "home"
elif st.session_state.page == "insert":
    if st.session_state.logged_in:
        insert_page()
    else:
        st.session_state.page = "home"
elif st.session_state.page == "retrieve":
    if st.session_state.logged_in:
        retrieve_page()
    else:
        st.session_state.page = "home"

 # OioLBEDJesmxvPI7_b7E40mWVC5l1sOt1sdKu5-arDw=