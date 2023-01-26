import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import pyperclip 

def encrypt(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message)
    return [base64.b64encode(nonce).decode('utf-8'),
            base64.b64encode(ciphertext).decode('utf-8'),
            base64.b64encode(tag).decode('utf-8')]

# Génération de la clé
key = get_random_bytes(16)

# Enregistrement de la clé dans un fichier
with open("key.bin", "wb") as key_file:
    key_file.write(key)

# Chiffrement du message
message = input("Entrer le message à chiffrer : ").encode('utf-8') 
enc_message = encrypt(message, key)

# Enregistrement du message chiffré dans un fichier
with open("encrypted_message.txt", "w") as enc_file:
    enc_file.write(str(enc_message))

# Copie du message chiffré dans le presse-papiers
pyperclip.copy(str(enc_message))
