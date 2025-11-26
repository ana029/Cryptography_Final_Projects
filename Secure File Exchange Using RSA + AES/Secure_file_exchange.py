# Task 2 - Secure File Exchange (Hybrid Encryption)
# This script shows how Alice can send a file securely to Bob
# using RSA for encrypting the AES key and AES for encrypting the file itself.

from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# 1) Bob generates an RSA key pair (public + private)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Save the keys to files because the assignment requires it
with open("private.pem", "wb") as f:
    f.write(private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ))

with open("public.pem", "wb") as f:
    f.write(public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ))

# 2) Alice creates a plaintext message file
message = b"This is Alice's secret file, sent securely using RSA + AES."
with open("alice_message.txt", "wb") as f:
    f.write(message)

# Compute the SHA-256 hash of the original message for integrity check later
hash1 = hashes.Hash(hashes.SHA256())
hash1.update(message)
original_hash = hash1.finalize()

# 3) Alice generates a random AES-256 key and IV
aes_key = os.urandom(32)    # AES-256 = 32 bytes
iv = os.urandom(16)         # IV for CBC mode = 16 bytes

# 4) Alice encrypts the plaintext file using AES-256-CBC
# AES in CBC mode requires PKCS7 padding
padder = padding.PKCS7(128).padder()
padded_msg = padder.update(message) + padder.finalize()

cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
encryptor = cipher.encryptor()
ciphertext = encryptor.update(padded_msg) + encryptor.finalize()

# Store IV + ciphertext together in one file
with open("encrypted_file.bin", "wb") as f:
    f.write(iv + ciphertext)

# 5) Alice encrypts the AES key using Bob's RSA public key
encrypted_aes_key = public_key.encrypt(
    aes_key,
    rsa_padding.OAEP(
        mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

with open("aes_key_encrypted.bin", "wb") as f:
    f.write(encrypted_aes_key)

# 6) Bob decrypts the AES key using his RSA private key
decrypted_aes_key = private_key.decrypt(
    encrypted_aes_key,
    rsa_padding.OAEP(
        mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# 7) Bob decrypts the AES-encrypted file using the decrypted AES key
# Read the encrypted file (first 16 bytes = IV, rest = ciphertext)
with open("encrypted_file.bin", "rb") as f:
    data = f.read()

iv_loaded = data[:16]
ciphertext_loaded = data[16:]

cipher_dec = Cipher(algorithms.AES(decrypted_aes_key), modes.CBC(iv_loaded))
decryptor = cipher_dec.decryptor()
decrypted_padded = decryptor.update(ciphertext_loaded) + decryptor.finalize()

unpadder = padding.PKCS7(128).unpadder()
decrypted_msg = unpadder.update(decrypted_padded) + unpadder.finalize()

# Save the final decrypted message
with open("decrypted_message.txt", "wb") as f:
    f.write(decrypted_msg)

# 8) Bob checks integrity using SHA-256 hash comparison
hash2 = hashes.Hash(hashes.SHA256())
hash2.update(decrypted_msg)
new_hash = hash2.finalize()

print("Original SHA256:", original_hash.hex())
print("Decrypted SHA256:", new_hash.hex())
print("Integrity OK:", original_hash == new_hash)
