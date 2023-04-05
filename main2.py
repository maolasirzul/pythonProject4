import random
import pyotp
import json
from sklearn.ensemble import IsolationForest
'''
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
'''
# IDS Component
def train_ids_model(data):
    model = IsolationForest(contamination=0.1)
    model.fit(data)
    return model

def detect_intrusion(model, test_data):
    return model.predict(test_data)

# Encryption Component
def generate_aes_key():
    return get_random_bytes(32)

def encrypt_aes(plaintext, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return cipher.nonce, ciphertext, tag

def decrypt_aes(nonce, ciphertext, tag, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_rsa(plaintext, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.encrypt(plaintext.encode())

def decrypt_rsa(ciphertext, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(ciphertext).decode()

# Multi-factor Authentication Component
def generate_totp_secret():
    return pyotp.random_base32()

def generate_totp_token(secret):
    totp = pyotp.TOTP(secret)
    return totp.now()

def verify_totp_token(secret, token):
    totp = pyotp.TOTP(secret)
    return totp.verify(token)
#=============train dataset============
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from sklearn.model_selection import train_test_split

def preprocess_data(file_path):
    # Load the dataset
    columns = [...]  # Provide the appropriate column names for the dataset
    data = pd.read_csv(file_path, names=columns)

    # Encode categorical features
    le = LabelEncoder()
    for column in data.columns:
        if data[column].dtype == 'object':
            data[column] = le.fit_transform(data[column])

    # Scale numerical features
    scaler = MinMaxScaler()
    data = pd.DataFrame(scaler.fit_transform(data), columns=data.columns)

    return data

def train_ids_model(train_data):
    X_train, X_test = train_test_split(train_data, test_size=0.2, random_state=42)

    # Train the Isolation Forest model
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(X_train)

    # Test the model
    y_pred = model.predict(X_test)
    y_pred[y_pred == 1] = 0  # Label normal data as 0
    y_pred[y_pred == -1] = 1  # Label anomalous data as 1

    return model

if __name__ == "__main__":
    # Preprocess the dataset
    file_path = "jetbrains://pycharm/navigate/reference?project=pythonProject4&path=NSL_KDD-master/20 Percent Training Set.csv"
    data = preprocess_data(file_path)

    # Train the IDS model
    model = train_ids_model(data)

#===================
# Example Usage
if __name__ == "__main__":
    # Train your IDS model with appropriate data
    model = train_ids_model(train_data)

    # Use the model to detect intrusions
    # Example: intrusion = detect_intrusion(model, test_data)

    # Generate AES and RSA keys
    aes_key = generate_aes_key()
    private_key, public_key = generate_rsa_keys()

    # Encrypt and decrypt using AES
    plaintext = "Sensitive healthcare data"
    nonce, ciphertext, tag = encrypt_aes(plaintext, aes_key)
    decrypted_text = decrypt_aes(nonce, ciphertext, tag, aes_key)
    print(decrypted_text)

    # Encrypt and decrypt using RSA
    ciphertext = encrypt_rsa(plaintext, public_key)
    decrypted_text = decrypt_rsa(ciphertext, private_key)
    print(decrypted_text)

    # Generate and verify TOTP tokens
    secret = generate_totp_secret()

