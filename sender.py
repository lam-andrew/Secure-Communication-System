from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad
import secrets
import base64

def generate_aes_key():
    # Generate a random 16-byte AES key
    return get_random_bytes(16)

def encrypt_rsa(public_key_path, aes_key):
    # Encrypt AES key with recipient's RSA public key
    recipient_key = RSA.import_key(open(public_key_path).read())
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_aes_key = cipher_rsa.encrypt(aes_key)
    return enc_aes_key

def encrypt_aes(aes_key, plaintext):
    # Pad the plaintext to the appropriate block size
    plaintext = pad(plaintext, AES.block_size)
    
    # Encrypt plaintext message with AES
    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    ciphertext = cipher_aes.encrypt(plaintext)
    
    return ciphertext

def generate_mac(key, data):
    # Generate HMAC using SHA-256 for message integrity
    h = HMAC.new(key, digestmod=SHA256)
    h.update(data)
    return h.digest()

def write_transmitted_data(encrypted_message, encrypted_aes_key, mac, mac_key):
    # Encode encrypted message, encrypted AES key, MAC, and MAC key using base64
    encoded_message = base64.b64encode(encrypted_message)
    encoded_aes_key = base64.b64encode(encrypted_aes_key)
    encoded_mac = base64.b64encode(mac)
    encoded_mac_key = base64.b64encode(mac_key)

    delimiter = b'|||'
    data = encoded_message + delimiter + encoded_aes_key + delimiter + encoded_mac + delimiter + encoded_mac_key
    with open("Transmitted_Data", "wb") as file:
        file.write(data)

# Read plaintext message from file
with open("plaintext_message.txt", "rb") as file:
    plaintext = file.read()

# Step 1: Generate AES key
aes_key = generate_aes_key()

# Step 2: Encrypt message with AES
encrypted_message = encrypt_aes(aes_key, plaintext)

# Step 3: Encrypt AES key with RSA
public_key_path = "./rsa_receiver_key_pair/receiver_public_key.pem"
encrypted_aes_key = encrypt_rsa(public_key_path, aes_key)

# Step 4: Generate a secure random key
mac_key = secrets.token_bytes(32)  # 32 bytes for a 256-bit key
mac = generate_mac(mac_key, encrypted_message)

# Step 5: Write to "Transmitted_Data" file
write_transmitted_data(encrypted_message, encrypted_aes_key, mac, mac_key)