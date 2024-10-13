from hashlib import md5
from os import urandom
import urllib.request
import random
import os
import binascii
num_chars_to_insert = 50
from Crypto.Random import get_random_bytes

from hashlib import md5
from base64 import b64decode
from base64 import b64encode

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Posições aleatórias para inserção dos caracteres 'A'
insert_positions = sorted(random.sample(range(num_chars_to_insert), num_chars_to_insert))

def insert_a_random(data):
    position = random.randint(0, len(data)) # Gere uma posição aleatória
    return data[:position] + b'A' + data[position:]

def _pad(s):
    bs = AES.block_size
    pad_len = bs - (len(s) % bs)
    padding = bytes([pad_len] * pad_len)
    return s + padding

def _unpad(s):
    pad_len = data[-1]
    return data[:-pad_len]

def AESencrypt(key, input_file, output_file):
    iv = urandom(AES.block_size)
    iv_hex = binascii.hexlify(iv).decode('utf-8')

    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)

    with open(input_file, 'rb') as infile:
        plaintext = infile.read()
        encrypted_data = iv + cipher.encrypt(pad(plaintext, AES.block_size))

    # word_url = "https://www.mit.edu/~ecprice/wordlist.10000"
    # response = urllib.request.urlopen(word_url)
    # long_txt = response.read().decode()
    # words = long_txt.splitlines()

        
   # alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
   # random_letter = random.choice(alphabet)

   # positions = []
   # while len(positions) < 20:
   #     position = random.randint(0, len(encrypted_data))
   #     if position not in positions:
   #         positions.append(position)
   # positions.sort()

   # with open('test_crypt', 'wb') as asd:
   #     asd.write(encrypted_data)

   # position = random.randint(0, len(encrypted_data))
   # random_word = random.choice(words)
   # inserted_text = (
   #     b'kokab' + random_word.encode('utf-8') + random_letter.encode('utf-8') * 200 + b'koeb'
   # )
   # for i, position in enumerate(positions):
   #     encrypted_data = (
   #         encrypted_data[:position + i * len(inserted_text)] +
   #         inserted_text +
   #         encrypted_data[position + i * len(inserted_text):]
   #     )

    with open(output_file, 'wb') as outfile:
        outfile.write(encrypted_data)


import sys
password = sys.argv[2]
enc_file = sys.argv[1]
out_file = sys.argv[3]

if len(password) < 32:
    print(f"Use a 32 bytes password, for AES256-CBC! password length: {len(password)}")
    sys.exit(0)

enc_shellcode_name = out_file
print(f'{enc_file} {password}\n')
AESencrypt(password, enc_file, enc_shellcode_name)
print(f'encrypted shellcode saved as {enc_shellcode_name}')
