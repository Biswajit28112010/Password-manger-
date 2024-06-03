import hashlib
import os
import json

# Generate a key for simple XOR encryption
def generate_key():
    return os.urandom(16)

# Load or create encryption key
def load_key():
    try:
        with open("key.key", "rb") as key_file:
            key = key_file.read()
    except FileNotFoundError:
        key = generate_key()
        with open("key.key", "wb") as key_file:
            key_file.write(key)
    return key

# Simple XOR encryption/decryption
def xor_encrypt_decrypt(data, key):
    return ''.join(chr(ord(c) ^ key[i % len(key)]) for i, c in enumerate(data))

# Generate a salted hash of the password
def hash_password(password, salt, pepper):
    return hashlib.sha256((password + salt + pepper).encode()).hexdigest()

# Store user data securely
def store_user_data(username, password, website, pepper):
    salt = os.urandom(16).hex()
    hashed_password = hash_password(password, salt, pepper)
    user_data = {
        "username": username,
        "password": hashed_password,
        "salt": salt,
        "website": website
    }
    return user_data

# Save data to a JSON file
def save_data(data, key):
    encrypted_data = xor_encrypt_decrypt(json.dumps(data), key)
    with open("data.json", "w") as file:
        file.write(encrypted_data)

# Load data from a JSON file
def load_data(key):
    try:
        with open("data.json", "r") as file:
            encrypted_data = file.read()
            decrypted_data = xor_encrypt_decrypt(encrypted_data, key)
            return json.loads(decrypted_data)
    except FileNotFoundError:
        return []

def display_data(data):
    for entry in data:
        print(f"Website: {entry['website']}, Username: {entry['username']}, Password: {entry['password']}")

def main():
    key = load_key()
    pepper = "pepper_secret"  # This should be securely managed and not hardcoded

    data = load_data(key)

    while True:
        print("1. Add new entry")
        print("2. Display all entries")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            website = input("Enter website: ")
            username = input("Enter username: ")
            password = input("Enter password: ")

            new_entry = store_user_data(username, password, website, pepper)
            data.append(new_entry)
            save_data(data, key)
        elif choice == "2":
            display_data(data)
        elif choice == "3":
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
