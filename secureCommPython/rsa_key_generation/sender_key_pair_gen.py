from Crypto.PublicKey import RSA

# Generate an RSA key pair
sender_key = RSA.generate(2048)

# Save the public key to a file
with open("./rsa_sender_key_pair/sender_public_key.pem", "wb") as pub_file:
    pub_file.write(sender_key.publickey().export_key())

# Save the private key to a file (keep this secure)
with open("./rsa_sender_key_pair/sender_private_key.pem", "wb") as priv_file:
    priv_file.write(sender_key.export_key())
