import random
from Crypto.Cipher import AES
from diffiehellman import DiffieHellman

class Cipher:
    def __init__(self, key, nonce):
        self.key = key
        self.nonce = nonce

    def aes_encrypt(self, txt):
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=self.nonce)
        ciphertext, tag = cipher.encrypt_and_digest(txt)
        return ciphertext

    def aes_decrypt(self, cipher_text):
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=self.nonce)
        msg = cipher.decrypt(cipher_text)
        return msg.decode('utf-8')

    @staticmethod
    def get_dh_public_key():
        dh = DiffieHellman(group=14, key_bits=540)
        pk = dh.get_public_key()
        return dh, pk

    @staticmethod
    def get_dh_shared_key(dh_1, pk_2, lngth=32):  # <--- וודא שכתוב כאן lngth=32
        dh_shared = dh_1.generate_shared_key(pk_2)
        return dh_shared[:lngth]