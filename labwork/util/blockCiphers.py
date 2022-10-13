"""
    This file is a helper module for response program (T3INF9004: Cryptanalyses und Method-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)

    Functions:

    block_cipher_cbc_encrypt
    block_cipher_cbc_decrypt
    block_cipher_cbc
    block_cipher_ctr
    block_cipher_xex
"""
import base64

from util.helpers import bytes2int, int2bytes
from handlers.mulGF128Handler import mul_gf_128


# helper function to perform oracle queries
def oracle_block_cipher(api, key, value, encrypt):
    return api.query_oracle("block_cipher", {
        "operation": "encrypt" if encrypt else "decrypt",
        "key": key,
        "plaintext" if encrypt else "ciphertext": base64.b64encode(value).decode("utf-8")
    })["ciphertext" if encrypt else "plaintext"]


# encryption function for cbc mode
def block_cipher_cbc_encrypt(blocks, key, iv, api):
    for index in range(len(blocks)):

        block = blocks[index]

        # block xor with current vector (iv)
        block = bytes2int(block) ^ iv
        block = int2bytes(block)

        # oracle: encrypt block with key
        oracle = oracle_block_cipher(api, key, block, True)
        block = base64.b64decode(oracle)

        # next vector (iv) will be the result block
        iv = bytes2int(block)

        blocks[index] = block
    return blocks


# decryption function for cbc mode
def block_cipher_cbc_decrypt(blocks, key, iv, api):
    for index in range(len(blocks)):
        block = blocks[index]

        # save current vector; iv <- block;
        # block will get modified, but is required for the next block operation
        cv = iv
        iv = bytes2int(block)

        # oracle: decrypt block with key
        oracle = oracle_block_cipher(api, key, block, False)
        block = base64.b64decode(oracle)

        # block xor with current vector
        block = bytes2int(block) ^ cv
        blocks[index] = int2bytes(block)
    return blocks


# encryption/decryption function for cbc mode
def block_cipher_cbc(blocks, key, iv, api, encrypt):
    if encrypt:
        return block_cipher_cbc_encrypt(blocks, key, iv, api)
    else:
        return block_cipher_cbc_decrypt(blocks, key, iv, api)


# encryption/decryption function for ctr mode
def block_cipher_ctr(blocks, key, nonce, api):
    counter = 0
    for index in range(len(blocks)):
        # oracle: encrypt (nonce || counter) with key
        oracle = oracle_block_cipher(api, key, nonce + counter.to_bytes(byteorder="big", length=4), True)
        oracle = bytes2int(base64.b64decode(oracle))

        # inc counter
        counter += 1
        # keep counter in 32bit space
        counter %= (0b1 << 32) - 1

        # block xor encrypted (nonce || counter)
        block = blocks[index]
        block = bytes2int(block) ^ oracle
        blocks[index] = int2bytes(block)
    return blocks


# encryption/decryption function for xex mode
def block_cipher_xex(blocks, key, tweak, api, encrypt):

    # extract lower 16 bytes from key
    key1 = base64.b64decode(key)[:16]
    # encode it ready for oracle query
    key1 = base64.b64encode(key1).decode("utf-8")

    # extract upper 16 bytes from key
    key2 = base64.b64decode(key)[16:]
    # encode it ready for oracle query
    key2 = base64.b64encode(key2).decode("utf-8")

    # oracle: encrypt tweak with key2
    key2 = oracle_block_cipher(api, key2, tweak, True)
    key2 = bytes2int(base64.b64decode(key2))

    # block-wise operation
    for index in range(len(blocks)):
        block = blocks[index]

        # first xor of block with key2
        block = bytes2int(block) ^ key2
        block = int2bytes(block)

        # oracle: encrypt/decrypt block with key1
        oracle = oracle_block_cipher(api, key1, block, encrypt)
        block = bytes2int(base64.b64decode(oracle))

        # second xor of block with key2
        blocks[index] = int2bytes(block ^ key2)

        key2 = mul_gf_128(key2)

    return blocks
