from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# 1. User A generates RSA keys
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# save PEM files
with open("private_key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

with open("public_key.pem", "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

# 2. User B encrypts the message
message = b"My secret message"
with open("message.txt", "wb") as f:
    f.write(message)

# AES key
aes_key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(aes_key)
nonce = os.urandom(12)

ciphertext = aesgcm.encrypt(nonce, message, None)
with open("encrypted_message.bin", "wb") as f:
    f.write(nonce + ciphertext)

# Encrypt AES key using RSA
encrypted_aes_key = public_key.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
with open("aes_key_encrypted.bin", "wb") as f:
    f.write(encrypted_aes_key)

# 3. User A decrypts everything
# decrypt AES key
with open("aes_key_encrypted.bin", "rb") as f:
    enc_key = f.read()

dec_aes_key = private_key.decrypt(
    enc_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# decrypt message
with open("encrypted_message.bin", "rb") as f:
    data = f.read()
nonce = data[:12]
ciphertext = data[12:]

aesgcm2 = AESGCM(dec_aes_key)
plaintext = aesgcm2.decrypt(nonce, ciphertext, None)

with open("decrypted_message.txt", "wb") as f:
    f.write(plaintext)
