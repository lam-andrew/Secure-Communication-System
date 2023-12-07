from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
import hmac
import secrets
import base64
from Crypto.Util.Padding import unpad

def decrypt_rsa(private_key_path, encrypted_aes_key):
    # Decrypt AES key with receiver's RSA private key
    private_key = RSA.import_key(open(private_key_path).read())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    return aes_key

def decrypt_aes(aes_key, encrypted_message):
    # Decrypt encrypted message with AES
    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    decrypted_message = cipher_aes.decrypt(encrypted_message)

    try:
        # Remove padding using PKCS#7 unpadding
        unpadded_message = unpad(decrypted_message, AES.block_size)
        print("Unpadded Message:", unpadded_message)
    except ValueError as e:
        print("Error during unpadding:", e)
        return None

    return unpadded_message

def verify_mac(key, data, received_mac):
    # Verify the MAC to ensure message integrity
    h = HMAC.new(key, digestmod=SHA256)
    h.update(data)
    calculated_mac = h.digest()
    return hmac.compare_digest(calculated_mac, received_mac)

# Read "Transmitted_Data" file
with open("Transmitted_Data", "rb") as file:
    data = file.read()
    delimiter = b'|||'
    transmitted_data = data.split(delimiter)

    # Decode base64-encoded data
    encoded_message = base64.b64decode(transmitted_data[0])
    encoded_aes_key = base64.b64decode(transmitted_data[1])
    encoded_mac = base64.b64decode(transmitted_data[2])
    encoded_mac_key = base64.b64decode(transmitted_data[3])

# Step 1: Decrypt AES key with RSA
private_key_path = "./rsa_receiver_key_pair/receiver_private_key.pem"
aes_key = decrypt_rsa(private_key_path, encoded_aes_key)

# Step 2: Decrypt message with AES
decrypted_message = decrypt_aes(aes_key, encoded_message)

# Step 3: Verify MAC
mac_key = encoded_mac_key  # Same key as in the sender program
if verify_mac(mac_key, encoded_message, encoded_mac):
    try:
        decoded_message = decrypted_message.decode("utf-8", errors='replace')
        print("Message received and authenticated successfully:")
        print(decoded_message)
    except UnicodeDecodeError as utf8_error:
        print("Unable to decode message as UTF-8:", utf8_error)
        decoded_message = decrypted_message.decode("latin-1", errors='replace')
        print("Decoded message using latin-1 encoding:")
        print(decoded_message)
else:
    print("MAC verification failed. Message integrity compromised.")
