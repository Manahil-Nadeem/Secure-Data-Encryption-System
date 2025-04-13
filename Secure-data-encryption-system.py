import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import uuid

# Generate a key (this should be stored securely in production)
if 'KEY' not in st.session_state:
    st.session_state.KEY = Fernet.generate_key()
cipher = Fernet(st.session_state.KEY)

# In-memory storage
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

if 'authorized' not in st.session_state:
    st.session_state.authorized = True

# Hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt text
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt with validation
def decrypt_data(encrypted_text, passkey):
    hashed = hash_passkey(passkey)

    for key, record in st.session_state.stored_data.items():
        if record["encrypted_text"] == encrypted_text and record["passkey"] == hashed:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    
    st.session_state.failed_attempts += 1
    return None

# UI
st.title("**_🔐 Secure Data Encryption System!_**")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("📁 **_MENU_**", menu)

# Home
if choice == "Home":
    st.subheader("**_🏠 Welcome_**")
    st.write("*Store and retrieve sensitive data securely using your own passkey.*")

# Store Data
elif choice == "Store Data":
    st.subheader("📝 Store New Data")
    user_data = st.text_area("Enter data to encrypt:")
    passkey = st.text_input("Enter a secure passkey:", type="password")

    if st.button("Encrypt & Store"):
        if user_data and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(user_data)
            unique_id = str(uuid.uuid4())  # Create a unique ID for each entry
            st.session_state.stored_data[unique_id] = {
                "encrypted_text": encrypted,
                "passkey": hashed
            }
            st.success("✅ Data encrypted and stored!")
            st.write("🔐 Encrypted text (save this to decrypt):")
            st.code(encrypted)
        else:
            st.error("⚠️ Please fill in all fields.")

# Retrieve Data
elif choice == "Retrieve Data":
    if not st.session_state.authorized:
        st.warning("🔒 Too many failed attempts. Please login again.")
        st.stop()

    st.subheader("🔍 Retrieve Your Data")
    encrypted_input = st.text_area("Paste your encrypted text:")
    passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey:
            result = decrypt_data(encrypted_input, passkey)
            if result:
                st.success("✅ Decryption successful!")
                st.write("📄 Your original data:")
                st.code(result)
            else:
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey. Attempts left: {remaining}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🚫 Locked out. Please reauthorize.")
                    st.session_state.authorized = False
                    st.experimental_rerun()  # Consider a more persistent lockout mechanism
        else:
            st.error("⚠️ All fields are required.")

# Login Page
elif choice == "Login":
    st.subheader("**_🔑 Reauthorization_**")
    password = st.text_input("Enter admin password:", type="password")
    if st.button("Login"):
        if password == "sir1234":  # In production, use a secure method
            st.session_state.failed_attempts = 0
            st.session_state.authorized = True
            st.success("**_✅ Reauthorized! You can now retrieve data again._**")
        else:
            st.error("❌ Incorrect admin password.")
