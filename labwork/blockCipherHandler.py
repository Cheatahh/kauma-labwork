import base64

from labwork.mulGF128Handler import mul_gf_128_handler


def perform_block_cipher_cbc(assignment, session):
    block_size = 16
    plaintext = base64.b64decode(assignment["plaintext"])
    iv = int.from_bytes(base64.b64decode(assignment["iv"]), byteorder="little")

    blocks = [plaintext[(block_size*index):(block_size*(index + 1))] for index in range(int(len(plaintext) / block_size))]

    for index in range(len(blocks)):
        blocks[index] = int.to_bytes(int.from_bytes(blocks[index], byteorder="little") ^ iv, byteorder="little", length=block_size)
        res = session.post("https://dhbw.johannes-bauer.com/lwsub/oracle/block_cipher", headers={"Accept": "application/json", "Content-Type": "application/json"},
                      json={
                          "operation": "encrypt",
                          "key": assignment["key"],
                          "plaintext": base64.b64encode(blocks[index]).decode("utf-8")
                      })
        blocks[index] = base64.b64decode(res.json()['ciphertext'])
        iv = int.from_bytes(blocks[index], byteorder="little")

    return {
        "ciphertext": base64.b64encode(b"".join(blocks)).decode("utf-8")
    }

def perform_block_cipher_cbc_dec(assignment, session):
    block_size = 16
    plaintext = base64.b64decode(assignment["ciphertext"])
    iv = int.from_bytes(base64.b64decode(assignment["iv"]), byteorder="little")

    blocks = [plaintext[(block_size*index):(block_size*(index + 1))] for index in range(int(len(plaintext) / block_size))]

    for index in range(len(blocks)):
        thisIv = iv
        iv = int.from_bytes(blocks[index], byteorder="little")
        res = session.post("https://dhbw.johannes-bauer.com/lwsub/oracle/block_cipher",
                            headers={"Accept": "application/json", "Content-Type": "application/json"},
                            json={
                                "operation": "decrypt",
                                "key": assignment["key"],
                                "ciphertext": base64.b64encode(blocks[index]).decode("utf-8")
                            })
        blocks[index] = int.to_bytes(int.from_bytes(base64.b64decode(res.json()['plaintext']), byteorder="little") ^ thisIv, byteorder="little", length=block_size)

    return {
        "plaintext": base64.b64encode(b"".join(blocks)).decode("utf-8")
    }

def perform_block_cipher_ctr(assignment, session):
    block_size = 16
    plaintext = base64.b64decode(assignment["plaintext"])
    nonce = base64.b64decode(assignment["nonce"])

    blocks = [plaintext[(block_size * index):(block_size * (index + 1))] for index in range(int(len(plaintext) / block_size))]

    counter = 0

    for index in range(len(blocks)):

        res = session.post("https://dhbw.johannes-bauer.com/lwsub/oracle/block_cipher", headers={"Accept": "application/json", "Content-Type": "application/json"},
                            json={
                                "operation": "encrypt",
                                "key": assignment["key"],
                                "plaintext": base64.b64encode(
                                    nonce + int.to_bytes(counter, byteorder="big", length=4)).decode(
                                    "utf-8")
                            })
        counter += 1

        blocks[index] = int.to_bytes(int.from_bytes(base64.b64decode(res.json()['ciphertext']), byteorder="little") ^ int.from_bytes(blocks[index], byteorder="little"), byteorder="little",
                                     length=block_size)

    return {
        "ciphertext": base64.b64encode(b"".join(blocks)).decode("utf-8")
    }


def perform_block_cipher_ctr_dec(assignment, session):
    block_size = 16
    plaintext = base64.b64decode(assignment["ciphertext"])
    nonce = base64.b64decode(assignment["nonce"])

    blocks = [plaintext[(block_size * index):(block_size * (index + 1))] for index in
              range(int(len(plaintext) / block_size))]

    counter = 0

    for index in range(len(blocks)):
        res = session.post("https://dhbw.johannes-bauer.com/lwsub/oracle/block_cipher",
                            headers={"Accept": "application/json", "Content-Type": "application/json"},
                            json={
                                "operation": "encrypt",
                                "key": assignment["key"],
                                "plaintext": base64.b64encode(
                                    nonce + int.to_bytes(counter, byteorder="big", length=4)).decode(
                                    "utf-8")
                            })
        counter += 1

        blocks[index] = int.to_bytes(
            int.from_bytes(base64.b64decode(res.json()['ciphertext']), byteorder="little") ^ int.from_bytes(
                blocks[index], byteorder="little"), byteorder="little",
            length=block_size)

    return {
        "plaintext": base64.b64encode(b"".join(blocks)).decode("utf-8")
    }

def perform_block_cipher_xex(assignment, session):
    block_size = 16
    plaintext = base64.b64decode(assignment["plaintext"])
    key1 = int.from_bytes(base64.b64decode(assignment["key"])[:16], byteorder="little")
    key2 = int.from_bytes(base64.b64decode(assignment["key"])[16:], byteorder="little")

    blocks = [plaintext[(block_size * index):(block_size * (index + 1))] for index in range(int(len(plaintext) / block_size))]

    key2res = session.post("https://dhbw.johannes-bauer.com/lwsub/oracle/block_cipher", headers={"Accept": "application/json", "Content-Type": "application/json"},
                            json={
                                "operation": "encrypt",
                                "key": base64.b64encode(int.to_bytes(key2, byteorder="little", length=block_size)).decode("utf-8"),
                                "plaintext": assignment["tweak"]
                            }).json()["ciphertext"]


    for index in range(len(blocks)):

        key2 = int.from_bytes(base64.b64decode(key2res), byteorder="little")

        key2res = mul_gf_128_handler({"block": key2res}, session)["block_times_alpha"]

        blocks[index] = int.to_bytes(int.from_bytes(blocks[index], byteorder="little") ^ key2, byteorder="little", length=block_size)

        res = session.post("https://dhbw.johannes-bauer.com/lwsub/oracle/block_cipher", headers={"Accept": "application/json", "Content-Type": "application/json"},
                            json={
                                "operation": "encrypt",
                                "key": base64.b64encode(int.to_bytes(key1, byteorder="little", length=block_size)).decode("utf-8"),
                                "plaintext": base64.b64encode(blocks[index]).decode("utf-8")
                            })

        blocks[index] = base64.b64decode(res.json()["ciphertext"])

        blocks[index] = int.to_bytes(int.from_bytes(blocks[index], byteorder="little") ^ key2, byteorder="little",
                                     length=block_size)

    return {
        "ciphertext": base64.b64encode(b"".join(blocks)).decode("utf-8")
    }

def perform_block_cipher_xex_dec(assignment, session):
    block_size = 16
    plaintext = base64.b64decode(assignment["ciphertext"])
    key1 = int.from_bytes(base64.b64decode(assignment["key"])[:16], byteorder="little")
    key2 = int.from_bytes(base64.b64decode(assignment["key"])[16:], byteorder="little")

    blocks = [plaintext[(block_size * index):(block_size * (index + 1))] for index in range(int(len(plaintext) / block_size))]

    key2res = session.post("https://dhbw.johannes-bauer.com/lwsub/oracle/block_cipher", headers={"Accept": "application/json", "Content-Type": "application/json"},
                            json={
                                "operation": "encrypt",
                                "key": base64.b64encode(int.to_bytes(key2, byteorder="little", length=block_size)).decode("utf-8"),
                                "plaintext": assignment["tweak"]
                            }).json()["ciphertext"]


    for index in range(len(blocks)):
        key2 = int.from_bytes(base64.b64decode(key2res), byteorder="little")
        key2res = mul_gf_128_handler({"block": key2res}, session)["block_times_alpha"]

        blocks[index] = int.to_bytes(int.from_bytes(blocks[index], byteorder="little") ^ key2, byteorder="little", length=block_size)

        res = session.post("https://dhbw.johannes-bauer.com/lwsub/oracle/block_cipher", headers={"Accept": "application/json", "Content-Type": "application/json"},
                            json={
                                "operation": "decrypt",
                                "key": base64.b64encode(int.to_bytes(key1, byteorder="little", length=block_size)).decode("utf-8"),
                                "ciphertext": base64.b64encode(blocks[index]).decode("utf-8")
                            })

        blocks[index] = base64.b64decode(res.json()["plaintext"])

        blocks[index] = int.to_bytes(int.from_bytes(blocks[index], byteorder="little") ^ key2, byteorder="little",
                                     length=block_size)

    return {
        "plaintext": base64.b64encode(b"".join(blocks)).decode("utf-8")
    }


def block_cipher_handler(assignment, session):
    operation = assignment["operation"]
    mode = assignment["opmode"]
    if mode == "cbc":
        if operation == "encrypt":
            return perform_block_cipher_cbc(assignment, session)
        else:
            return perform_block_cipher_cbc_dec(assignment, session)
    elif mode == "ctr":
        if operation == "encrypt":
            return perform_block_cipher_ctr(assignment, session)
        else:
            return perform_block_cipher_ctr_dec(assignment, session)
    else:
        if operation == "encrypt":
            return perform_block_cipher_xex(assignment, session)
        else:
            return perform_block_cipher_xex_dec(assignment, session)
