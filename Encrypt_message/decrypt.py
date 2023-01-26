import base64
from Crypto.Cipher import AES
import pyperclip 

def decrypt(enc_message, key):
    nonce = base64.b64decode(enc_message[0])
    ciphertext = base64.b64decode(enc_message[1])
    tag = base64.b64decode(enc_message[2])
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    return cipher.decrypt(ciphertext)

# Chargement de la clé depuis le fichier
with open("key.bin", "rb") as key_file:
    key = key_file.read()

# Chargement du message chiffré depuis le fichier
with open("encrypted_message.txt", "r") as enc_file: 
    enc_message = eval(enc_file.read())

# Déchiffrement du message
dec_message = decrypt(enc_message, key).decode('utf-8')
print()
print(dec_message)
print()

# Copie du message déchiffré dans le presse-papiers
pyperclip.copy(str(dec_message))
