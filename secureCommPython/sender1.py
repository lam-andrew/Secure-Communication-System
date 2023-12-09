from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad
import hmac
import os

def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open("./rsa_sender_key_pair/sender_private_key.pem", "wb") as private_key_file:
        private_key_file.write(private_key)
    with open("./rsa_receiver_key_pair/receiver_public_key.pem", "wb") as public_key_file:
        public_key_file.write(public_key)

def encrypt_message():
    with open("plaintext_message.txt", "r") as file:
        plaintext_message = file.read()

    aes_key = os.urandom(32)
    recipient_public_key = RSA.import_key(open("./rsa_receiver_key_pair/receiver_public_key.pem").read())
    cipher_rsa = PKCS1_OAEP.new(recipient_public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    # Pad the plaintext to a multiple of the block size
    plaintext_padded = pad(plaintext_message.encode(), AES.block_size)
    ciphertext = cipher_aes.encrypt(plaintext_padded)

    mac_key = os.urandom(32)  # Generate a random key for HMAC
    mac = generate_mac(mac_key, encrypted_aes_key + ciphertext)

    with open("Transmitted_Data", "wb") as file:
        file.write(encrypted_aes_key)
        file.write(ciphertext)
        file.write(mac_key)  # Include the MAC key in the transmitted data
        file.write(mac)

    # Save the MAC key to a local file
    with open("mac_key.txt", "wb") as mac_file:
        mac_file.write(mac_key)

def generate_mac(key, data):
    h = hmac.new(key, digestmod=SHA256)
    h.update(data)
    return h.digest()

if __name__ == "__main__":
    generate_rsa_key_pair()
    encrypt_message()
