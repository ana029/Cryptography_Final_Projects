# Computes SHA256, SHA1, and MD5 for a file
# Stores hashes in JSON and later detects tampering

import hashlib
import json

# -------------------------------------------
# Function to calculate all 3 hashes
# -------------------------------------------
def calculate_hashes(filename):
    with open(filename, "rb") as f:
        data = f.read()

    # Compute hashes
    sha256 = hashlib.sha256(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()

    # Return them in a dictionary
    return {
        "sha256": sha256,
        "sha1": sha1,
        "md5": md5
    }

# -------------------------------------------
# Step 1: Compute and save original hashes
# -------------------------------------------
print("Calculating hashes for original.txt ...")
original_hashes = calculate_hashes("original.txt")

# Save to JSON file
with open("hashes.json", "w") as f:
    json.dump(original_hashes, f, indent=4)

print("Hashes saved to hashes.json\n")

# -------------------------------------------
# Step 2: Compute hashes for the tampered file
# -------------------------------------------
print("Checking tampered file integrity...")
tampered_hashes = calculate_hashes("tampered.txt")

# Load stored original hashes
with open("hashes.json", "r") as f:
    saved_hashes = json.load(f)

# -------------------------------------------
# Step 3: Compare hashes
# -------------------------------------------
integrity_ok = (saved_hashes == tampered_hashes)

if integrity_ok:
    print("Integrity Check: PASS (File not modified)")
else:
    print("Integrity Check: FAIL (File has been tampered!)")

print("\nOriginal Hashes:", saved_hashes)
print("Current Hashes :", tampered_hashes)
