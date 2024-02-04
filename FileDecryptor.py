from OpenSSL import crypto
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from base64 import b64decode
import lzma
import os
from zipfile import ZipFile

class FileDecryptor:
    def __init__(self, data_path):
        self.data_path = data_path

    def evp_decrypt(self, key, ciphertext, iv):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext

    def get_bytes(self, num):
        x = num.to_bytes(0x10, 'big')
        if len(x) > 0:
            return x[-1]
        return 0

    def get_xor_file(self, filename):
        ret = []
        a = bytearray(filename, "ascii")
        for i in range(0, len(filename)):
            v28 = (bytes(filename[i], "ascii")[0] ^ len(filename)) + 0x69
            a[i] = v28
        return a

    def get_xor_key(self, file_data):
        return self.get_bytes(file_data[5] ^ 0x1337)

    def get_key(self, xored, xor_key):
        key = bytearray([0]*0x40)
        for i in range(0, 0x40, 8):
            curr = xored[(i + 105) % len(xored)]
            key[i] = self.get_bytes(curr)

            curr = (key[i] ^ xor_key) + 105
            key[i] = self.get_bytes(curr)   

            curr = xored[(i + 106) % len(xored)]
            key[i+1] = self.get_bytes(curr)

            curr = (key[i+1] ^ xor_key) + 105
            key[i+1] = self.get_bytes(curr)

            curr = xored[(i + 107) % len(xored)]
            key[i+2] = self.get_bytes(curr)

            curr = (key[i+2] ^ xor_key) + 105
            key[i+2] = self.get_bytes(curr)

            curr = xored[(i + 108) % len(xored)]
            key[i+3] = self.get_bytes(curr)

            curr = (key[i+3] ^ xor_key) + 105
            key[i+3] = self.get_bytes(curr)

            curr = xored[(i + 109) % len(xored)]
            key[i+4] = self.get_bytes(curr)

            curr = (key[i+4] ^ xor_key) + 105
            key[i+4] = self.get_bytes(curr)

            curr = xored[(i + 110) % len(xored)]
            key[i+5] = self.get_bytes(curr)

            curr = (key[i+5] ^ xor_key) + 105
            key[i+5] = self.get_bytes(curr)

            curr = xored[(i + 111) % len(xored)]
            key[i+6] = self.get_bytes(curr)

            curr = (key[i+6] ^ xor_key) + 105
            key[i+6] = self.get_bytes(curr)

            curr = xored[(i + 112) % len(xored)]
            key[i+7] = self.get_bytes(curr)

            curr = (key[i+7] ^ xor_key) + 105
            key[i+7] = self.get_bytes(curr)
        return bytes(key)

    def get_iv(self, filename, xor_key):
        iv = bytearray([0]*0x10)
        for j in range(0, 0x10, 8):
            v68 = 0
            if (j & 1) == 0:
                v68 = xor_key
            v69 = 0
            if ( j == 3 * (j // 3) ):
                v69 = 105
            iv[j] = self.get_bytes(v68 + v69)

            v71 = len(filename) + (iv[j]^xor_key)

            iv[j] = self.get_bytes(v71)

            v74 = j - 1
            v75 = 0

            if ( (j - 1) & 1) == 0:
                v75 = xor_key
            v76 = 0

            if j - 3 * ((v74 + 2) // 3) == -1:
                v76 = 105
            iv[j + 1] = self.get_bytes(v75 + v76)

            v78 = len(filename) + (iv[j+1]^xor_key)
            iv[j+1] = self.get_bytes(v78)

            v81 = 0

            if ( j - 3 * ((v74 + 3) // 3) == -2):
                v81 = 105
            iv[j+2] = self.get_bytes(v68 + v81)

            v83 = len(filename) + (iv[j+2]^xor_key)
            iv[j+2] = self.get_bytes(v83)

            v86 = 0
            if ( not(j + 2 * (1 - (v74 + 4) // 3) + 1 - (v74 + 4) // 3) ):
                v86 = 105
            iv[j + 3] = self.get_bytes(v75 + v86)

            v88 = len(filename) + (iv[j+3]^xor_key)
            iv[j+3] = self.get_bytes(v88)

            v91 = 0
            if ( j - 3 * ((v74 + 5) // 3) == -4):
                v91 = 105
            iv[j + 4] = self.get_bytes(v68 + v91)

            v93 = len(filename) + (iv[j+4]^xor_key)
            iv[j+4] = self.get_bytes(v93)

            v96 = 0
            if ( j - 3 * ((v74 + 6) // 3) == -5 ):
                v96 = 105
            iv[j+5] = self.get_bytes(v75 + v96)

            v98 = len(filename) + (iv[j+5]^xor_key)
            iv[j + 5] = self.get_bytes(v98)

            v101 = 0

            if ( not(-3 * ((v74 + 7) // 3) + j + 6) ):
                v101 = 105

            iv[j + 6] = self.get_bytes(v68 + v101)

            v103 = len(filename) + (iv[j+6]^xor_key)
            iv[j+6] = self.get_bytes(v103)

            v106 = 0
            if ( j - 3 * ((v74 + 8) // 3) == -7 ):
                v106 = 105
            iv[j + 7] = self.get_bytes(v75 + v106)

            v108 = len(filename) + (iv[j+7]^xor_key)
            iv[j+7] = self.get_bytes(v108)

        return iv

    def decrypt_file(self, file_path):
        file_name = os.path.basename(file_path)

        with open(file_path, 'rb') as encrypted_file:
            if encrypted_file.read(4) != b'P00P':
                print("Not poop, skipping: " + file_path)
                return
            encrypted_file.seek(0)
            xor_key2 = self.get_xor_key(bytearray(encrypted_file.read()))
            key = self.get_key(self.get_xor_file(file_name), xor_key2)
            iv = self.get_iv(file_name, xor_key2)

        with open(file_path, 'rb') as file:
            file.read(16)
            decompressed = lzma.decompress(self.evp_decrypt(key[:32], file.read(), iv))

        with open(file_path, 'wb') as new:
            new.write(decompressed)

    def decrypt_all_files(self):
        for root, _, files in os.walk(self.data_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                self.decrypt_file(file_path)