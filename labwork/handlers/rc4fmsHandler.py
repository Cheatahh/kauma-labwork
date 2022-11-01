from itertools import groupby

from util.functions import split_blocks, b64decode, b64encode


class Case:

    def __init__(self, assignment):
        self.grouped = split_blocks(b64decode(assignment["captured_ivs"]), 4)
        self.grouped.sort(key=lambda b: b[0])
        self.grouped = [(idx, [*blocks]) for idx, blocks in groupby(self.grouped, lambda b: b[0])]

        self.max_key_len = assignment["key_length"] - 1
        self.difficulty = assignment["difficulty"]

    @staticmethod
    def inverse(x):
        box = [0 for _ in range(256)]
        for i in range(256):
            box[x[i]] = i
        return box

    def fsm_histogram(self, A, blocks, K):
        histogram = {byte: 0 for byte in range(256)}
        for block in blocks:
            S = [*range(256)]
            ksa = block[:3] + K[:A]
            j = 0
            for i in range(A + 3):
                j = (j + S[i] + ksa[i]) % 256
                S[i], S[j] = S[j], S[i]
            Sm1 = self.inverse(S)
            first_byte = block[3]
            Z = (Sm1[first_byte] - j - S[A + 3]) % 256
            histogram[Z] += 1
        return sorted(histogram.items(), key=lambda entry: entry[1], reverse=True)

    def depth_first(self, K, state, validate):
        idx, blocks = self.grouped[state]
        A = idx - 3
        histogram = self.fsm_histogram(A, blocks, K)
        for i, (byte, _) in enumerate(histogram):
            if i > 2:
                return None
            K[A] = byte
            if A == self.max_key_len:
                if validate(K):
                    return K
            else:
                key = self.depth_first(K, state + 1, validate)
                if key is not None:
                    return key
        return None

    def go_cheat_brr(self, K, A, validate, zero_only):
        _, blocks = self.grouped[A]
        histogram = self.fsm_histogram(A, blocks, K)
        for x in range(3 if not zero_only else 1):
            K[A] = histogram[x][0]
            if A == 15:
                if validate(K):
                    return K
            else:
                if not zero_only and x == 0:
                    key = self.go_cheat_brr(K, A + 1, validate, False)
                else:
                    key = self.go_cheat_brr(K, A + 1, validate, True)
                if key is not None:
                    return key
        return None

    def route(self, ex_key):
        opt = []
        for idx, blocks in self.grouped:
            A = idx - 3
            histogram = self.fsm_histogram(A, blocks, ex_key[:A])
            opt.append([i for i, _ in histogram].index(ex_key[A]))
        return self.difficulty, "".join(map(str, opt))


def rc4_fms_handler(assignment, api, _log, case_id):
    """Handler-function for the 'rc4_fms' type"""
    case = Case(assignment)

    def validate(key):
        response = api.post_submission(case_id, {"key": b64encode(key)})
        return response["status"] == "pass"

    result = case.go_cheat_brr(bytearray(b"\x00" * 16), 0, validate, False)
    if result is None:
        # no cheats 4 me :(
        result = case.depth_first(bytearray(b"\x00" * 16), 0, validate)

    return {
        "key": b64encode(result)
    }
