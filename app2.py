from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import streamlit as st
import os
import json
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
import base64


# 加载私钥
def load_private_key():
    with open('private_key.pem', "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

# 加载公钥
def load_public_key():
    with open('public_key.pem', "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key

# 使用公钥加密
def encrypt_message(message):
    public_key = load_public_key()
    # 首先将消息编码为Base64格式
    message_base64 = base64.b64encode(message.encode()).decode()
    # 然后加密Base64编码后的字符串
    encrypted = public_key.encrypt(
        message_base64.encode(),  # 确保转换为bytes
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted)  # 将加密后的数据编码为Base64以便安全展示和传输

# 使用私钥解密
def decrypt_message(encrypted_message):
    private_key = load_private_key()
    # 首先对加密后的Base64字符串进行解码
    encrypted_message_bytes = base64.b64decode(encrypted_message)
    # 解密
    decrypted_base64 = private_key.decrypt(
        encrypted_message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # 将解密得到的Base64字符串解码回原始消息
    original_message = base64.b64decode(decrypted_base64).decode()
    return original_message



def main():
    st.title("Encrypt Entire Streamlit Session State")

    # 输入键名和值来修改或添加到session_state
    key = st.text_input("Enter key")
    value = st.text_input("Enter value")

    if st.button("Add/Update Session State"):
        if key:
            st.session_state[key] = value

    # 显示原始状态
    st.write("Original Session State:", st.session_state)

    # 序列化session_state为JSON字符串
    session_state_json = json.dumps(st.session_state.to_dict(), sort_keys=True)

    st.write("jsonfy Session State:", session_state_json)
    
    # 加密整个session_state
    encrypted_state = encrypt_message(session_state_json)

    # 显示加密后的状态（Base64字符串）
    st.write("Encrypted Session State (Base64):", encrypted_state)
    st.write(f'length is {len(encrypted_state)}')

    # 解密回JSON字符串
    decrypted_state_json = decrypt_message(encrypted_state)
    
    # 反序列化JSON字符串回字典
    decrypted_state = json.loads(decrypted_state_json)

    # 显示解密后的状态
    st.write("Decrypted Session State:", decrypted_state)

if __name__ == "__main__":
    main()
