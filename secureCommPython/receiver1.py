from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import unpad
import hmac
import os

def decrypt_message():
    with open("Transmitted_Data", "rb") as file:
        encrypted_aes_key = file.read(256)
        ciphertext = file.read()
        mac_key = file.read(32)  # Read the MAC key from the transmitted data
        mac_received = file.read(32)

    sender_private_key = RSA.import_key(open("./rsa_sender_key_pair/sender_private_key.pem").read())
    cipher_rsa = PKCS1_OAEP.new(sender_private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    # Calculate MAC using the received MAC key and ciphertext
    mac_calculated = generate_mac(mac_key, encrypted_aes_key + ciphertext)

    if mac_calculated == mac_received:
        cipher_aes = AES.new(aes_key, AES.MODE_CBC)
        decrypted_message = cipher_aes.decrypt(ciphertext)
        # Remove padding from the decrypted message
        decrypted_message = unpad(decrypted_message, AES.block_size).decode()
        print("Decrypted Message:", decrypted_message)
    else:
        print("Message authentication failed. Integrity compromised.")

def generate_mac(key, data):
    h = hmac.new(key, digestmod=SHA256)
    h.update(data)
    return h.digest()

if __name__ == "__main__":
    decrypt_message()
