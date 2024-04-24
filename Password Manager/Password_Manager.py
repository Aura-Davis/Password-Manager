from asyncio.windows_events import NULL
import base64
import os
import cryptography
from cryptography import fernet
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def create_key(mainPassword):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(mainPassword.encode()))
    with open("key.txt", "a") as key_file:
        key_file.write(mainPassword + "|" + key.decode() + "\n")
    return key
        
def load_key(given):
    res = NULL
    file = open("key.txt", "r")
    for line in file.readlines():
            data = line.rstrip()
            password, key = data.split("|")
            if given == password:
                res = key
    file.close()
    if res == NULL:
        return Fernet.generate_key()
    else:
        return res.encode()

mainPassword = input("Unlock Password: ")
isNew = input("New or Existing User: ").lower()
if isNew == "new":
    fer = Fernet(create_key(mainPassword))
else:
    fer = Fernet(load_key(mainPassword))

def view():
    with open('passwords.txt', 'r') as f:
        for line in f.readlines():
            data = line.rstrip()
            user, password = data.split("|")
            try:
                print("User:", user, "| Password:", fer.decrypt(password.encode()).decode())
            except (cryptography.fernet.InvalidToken, TypeError):
                pass

def add():
    name = input('Account Name: ')
    password = input("Password: ")
    
    with open('passwords.txt', 'a') as f:
        f.write(name + "|" + fer.encrypt(password.encode()).decode() + "\n")
        
while True:
    mode = input ("Add new password or view existing passwords: (view, add), press q to quit ").lower()
    if mode == 'q':
        break
    
    elif mode == "view":
        view()
    elif mode == "add":
        add()
    else:
        print("Invalid Input")
        continue