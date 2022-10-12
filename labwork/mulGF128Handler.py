import base64


def mul_gf_128_handler(assignment, session):
    """Handler-function for the 'caesar_cipher' type"""

    res = int.from_bytes(base64.b64decode(assignment["block"]), byteorder="little")

    result = res << 1

    if result & (0b1 << 128):
        result ^= 0b10000111
        result &= (0b1 << 128) - 1

    block = base64.b64encode(result.to_bytes(byteorder="little", length=16)).decode("utf-8")

    return {
        "block_times_alpha": block
    }

