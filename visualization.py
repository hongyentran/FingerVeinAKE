import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from io import StringIO
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
import pickle
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import time

def encrypt_data(data, key):
    cipher = Cipher(algorithms.AES(key), modes.CFB(os.urandom(16)), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return ciphertext

def decrypt_data(ciphertext, key):
    cipher = Cipher(algorithms.AES(key), modes.CFB(ciphertext[:16]), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return decrypted_data



if __name__ == '__main__':
    # dict = {'comm. cost': [392, 432, 344, 488], 'comp. cost': [407.92, 515.66, 407.96, 410.58]}
    dict = {'comm. cost': [147648, 392, 432, 344, 488], 'comp. cost': [151037.44, 407.92, 515.66, 407.96, 410.58]}
    df = pd.DataFrame.from_dict(dict)
    df.index = ['[18]', '[22]', '[28]', 'Our-1', 'Our-2']
    ax = df.plot(kind='bar', secondary_y='comp. cost', rot=0, figsize=(8,5))
    # plt.yticks(np.arange(0, 1, 0.1))
    # plt.xticks(np.arange(0, 1600, 100))

    # plt.ylabel("Comm. cost in bytes")
    ax.set_ylabel('Comm. cost in bytes')
    ax.right_ax.set_ylabel('Comp. cost in ms')
    # plt.title("Comparison of comm. cost and comp. cost between our scheme and others")
    plt.savefig('mfake-compare3.png')
    plt.show()