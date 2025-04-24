import streamlit as st
from cryptography.fernet import Fernet
import hashlib
import json
import os
import time
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac


DATA_FILE = 'secure_data.json'
SALT = b'secure_salt_value'
LOCK_DURATION = 30


if 'authenticated_user' not in st.session_state:
    st.session_state.authenticated_user = None

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

if 'lockout_time' not in st.session_state:
    st.session_state.lockout_time = 0

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    return{}

def save_data(data):
    with open(DATA_FILE, 'w') as f:
        return json.dump(data, f)
    
def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def encrypt_data(data, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(encrypt_data, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypt_data.encode()).decode()
    except:
        return None
    
    
stored_data = load_data()

st.set_page_config(page_title='Cipher Monster', page_icon='🛡️')

st.title('👾 Cipher Monster')
st.write('🛡️ Where Your Data Finds Safety.')

Menu = ['Home', 'Sign Up', 'Sign In', 'Store Data', 'Retrieve Data']

choice = st.sidebar.selectbox('Navigation', Menu)

if choice == 'Home':
    st.subheader('Welcome to Cipher Monster. Your go to place for enctypting data securely')

elif choice == 'Sign Up':
    st.subheader('Sign Up for Cipher Monster')
    user_name = st.text_input('Choose a user name')
    password = st.text_input('Choose a strong password', type='password')

    if st.button('Sign Up'):
        if user_name and password:
            if user_name in stored_data:
                st.warning('User already exists!')
            else:
                stored_data[user_name] = {
                    'password': hash_password(password),
                    'data': []
                }
                save_data(stored_data)
                st.success('SignUp successful.')

        else:
            st.error('Both fields are required')

elif choice == 'Sign In':
    st.subheader('Sign In to Cipher Monster')

    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f'Too many failed attempts. Please wait for {remaining}s ')
        st.stop()

    user_name = st.text_input('Username')
    password = st.text_input('Password', type='password')

    if st.button('SignIn'):
        
        if user_name in stored_data and stored_data[user_name]['password'] == hash_password(password):
            st.session_state.authenticated_user = user_name
            st.session_state.failed_attempts = 0
            st.success(f'Welcome back {user_name} to Cipher Monster')
            
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error(f'Invalid Creditentials! {remaining} attempts left.')

            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCK_DURATION
                st.error('Too many failed attempts. Please wait for 60s')
                st.stop()

elif choice == 'Store Data':
    
    if not st.session_state.authenticated_user:
        st.warning('Please Sign Up for continue')
    else:
        st.subheader('Store Your Private Data')
        data = st.text_area('Enter Data to Encrypt')
        passkey = st.text_input('Encryption Key', type='password')

        if st.button('Encrypt Data'):
            
            if data and passkey:
                encrypted = encrypt_data(data, passkey)
                stored_data[st.session_state.authenticated_user]['data'].append(encrypted)
                save_data(stored_data)
                st.success('Data Encrypted Successfully.')

            else:
                st.error('All Feilds are required to be filled')

elif choice == 'Retrieve Data':
    
    if not st.session_state.authenticated_user:
        st.warning('Please Sign Up to Continue')
        
    else:
        st.subheader('Retreive And Decrypt Your Data')
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get('data', [])

        if not user_data:
            st.info('No Data Found')
            
        else:
            st.write('Encrypted Data Enteries: ')
            
            for i, item in enumerate(user_data):
                st.code(item, language='text')
            
            encrypted_input = st.text_area('Enter Encrypted Text')
            passkey = st.text_input('Enter Passkey To Decrypt Data', type='password')

            if st.button('Dycrypt'):
                result = decrypt_data(encrypted_input, passkey)
                
                if result:
                    st.code(f'Decrypted Data: {result}')
                    
                else:
                    st.error('Incorrect Passkey or Username')