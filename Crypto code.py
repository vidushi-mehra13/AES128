from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt

# Generate a secure key using a key derivation function (KDF)
password = b'your_secure_password'
salt = get_random_bytes(16)
key = scrypt(password, salt, key_len=32, N=2**14, r=8, p=1)

# Encryption function
def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return ciphertext, cipher.nonce, tag

# Decryption function
def decrypt_message(ciphertext, nonce, tag, key):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted_message = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_message.decode()

plaintext = input("enter text to be encrypted")
ciphertext, nonce, tag = encrypt_message(plaintext, key)
decrypted_message = decrypt_message(ciphertext, nonce, tag, key)

print("Original message:", plaintext)
print("Encrypted message:", ciphertext)
print("Decrypted message:", decrypted_message)
print("Key used for encryption or decryption:", key.hex())
print("The Length of the key is", len(key), "bytes")
