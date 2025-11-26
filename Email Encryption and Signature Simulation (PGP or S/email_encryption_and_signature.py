# Task 4: Email Security (PGP-style Signing & Encryption)

import os
import gnupg

# 1) Setup GPG home directory
os.makedirs("gpg_home", exist_ok=True)

# NOTE: Path for Gpg4win installation on Windows.
gpg = gnupg.GPG(
    gnupghome="gpg_home",
    gpgbinary="C:/Program Files (x86)/GnuPG/bin/gpg.exe"
)

# 2) Generate key pairs for Alice and Bob
alice_input = gpg.gen_key_input(
    name_email="alice@example.com",
    passphrase="alicepass"
)
alice_key = gpg.gen_key(alice_input)

bob_input = gpg.gen_key_input(
    name_email="bob@example.com",
    passphrase="bobpass"
)
bob_key = gpg.gen_key(bob_input)

# 3) Export public and secret keys
# Export ONLY public keys (no passphrase needed)
with open("public.asc", "w") as f:
    f.write(gpg.export_keys([alice_key.fingerprint, bob_key.fingerprint]))

# Export secret keys → passphrase is REQUIRED by GnuPG 2.1+
with open("private.key", "w") as f:
    f.write(gpg.export_keys(
        [alice_key.fingerprint, bob_key.fingerprint],
        secret=True,
        passphrase="alicepass"   # we export Alice + Bob, so we can't leave this empty
    ))

# 4) Alice creates original message
original_message = "Hello Bob! This is a secret internal message."
with open("original_message.txt", "w") as f:
    f.write(original_message)

# 5) Alice signs + encrypts message for Bob
with open("original_message.txt", "rb") as f:
    gpg.encrypt_file(
        f,
        recipients=["bob@example.com"],
        sign="alice@example.com",
        passphrase="alicepass",   # needed for signing
        output="signed_message.asc"
    )

print("Signed & encrypted message saved as: signed_message.asc")

# 6) Bob decrypts + verifies Alice's signature
with open("signed_message.asc", "rb") as f:
    decrypted = gpg.decrypt_file(
        f,
        passphrase="bobpass",
        output="decrypted_message.txt"
    )

# Create signature verification report
verification_text = (
    f"Signature valid: {decrypted.valid}\n"
    f"Signed by: {decrypted.username}\n"
)

with open("signature_verification.txt", "w") as f:
    f.write(verification_text)

print("Decrypted message saved to: decrypted_message.txt")
print("Signature verification saved to: signature_verification.txt")
