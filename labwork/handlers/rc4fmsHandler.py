"""
    This file is a handler module for response program (T3INF9004: Cryptanalysis und Method-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)
    Component: Labwork05

    Functions:

    rc4_fms_handler
"""

from itertools import groupby

from util.functions import split_blocks, b64decode, b64encode


# this class is used to represent a cached state of the search tree
class Node:

    def __init__(self, A, grouped, K):
        # note: as the histogram evaluation is the most expensive part of the algorithm, we cache the result
        # However, this will result in an increased memory usage (~2.6gb for a search depth of 3).
        # If you want to reduce the memory usage, you can remove the histogram caching and
        # reevaluate the histogram with each call to df_bs_search.
        self.histogram = Node.fsm_histogram(A, grouped[A][1], K)
        if A == 15:
            self.nodes = 0
        else:
            self.nodes = []

    # inverse an s-box from index -> value to value -> index
    @staticmethod
    def inverse(x):
        box = [0 for _ in range(256)]
        for i in range(256):
            box[x[i]] = i
        return box

    # evaluate the probability of a given key characters
    # i.o.w. generate a histogram
    @staticmethod
    def fsm_histogram(A, blocks, K):
        histogram = {byte: 0 for byte in range(256)}
        for block in blocks:
            S = [*range(256)]
            ksa = block[:3] + K[:A]
            j = 0
            # regular ksa
            for i in range(A + 3):
                j = (j + S[i] + ksa[i]) % 256
                S[i], S[j] = S[j], S[i]
            # extract most probable key character Z
            Sm1 = Node.inverse(S)
            first_byte = block[3]
            Z = (Sm1[first_byte] - j - S[A + 3]) % 256
            histogram[Z] += 1
        # descending order, as the most probable key is the one with the most occurrences (entry[1])
        return sorted(histogram.items(), key=lambda entry: entry[1], reverse=True)

    # back-tracking (depth-first) search with accommodating breadth stepping (progressive breadth)
    # This algorithm is mutated to use nested nodes layers instead of functional recursion. They allow
    # us to keep track of already processed branches, so we can skip them in the future, as an increased
    # search breadth will also include all branches of previously processed breadths.
    def df_bs_search(self, A, grouped, K, validate):
        # histogram = fsm_histogram(A, grouped[A][1], K)  # do not cache the histogram
        histogram = self.histogram

        # Node is in last layer
        if A == 15:
            depth = self.nodes
            if depth == 256:
                return None
            # try to newly added breadth
            # noinspection PyTypeChecker
            K[A] = histogram[depth][0]
            # if the key is valid, return it
            # note: here could be a print (use the log obj from the handler pls) to view the current path
            # (interesting for debugging and analysis of the algorithm)
            if validate(K):
                return K
            self.nodes += 1

        # Node is in an inbetween layer (including first layer)
        else:
            depth = len(self.nodes)
            if depth == 256:
                return None
            # add newly added breadth
            K[A] = histogram[depth][0]
            node = Node(A + 1, grouped, K)
            # first stage of newly added breadth
            # prefer 0' branches, f.e. the total path 0000100000000000 will come fairly early
            # on an increased search breadth of 1
            res = node.df_bs_search(A + 1, grouped, K, validate)
            if res is not None:
                return res
            # revisit all previously processed branches of previously processed breadths
            # process all remaining branches with the newly added breadth
            for x in range(depth):
                K[A] = histogram[x][0]
                res = self.nodes[x].df_bs_search(A + 1, grouped, K, validate)
                if res is not None:
                    return res
            # secondary stages of newly added breadth
            # process all other branches of the newly added breadth
            for x in range(depth):  # remove loop = cheat mode, but will not find all keys
                res = node.df_bs_search(A + 1, grouped, K, validate)
                if res is not None:
                    return res
            # add newly added breadth to the node pool
            self.nodes.append(node)

    # cheaty way, but will not find all keys
    # Observation by analysing used routes with an expected key:
    # There will only be one junction in the search tree, where the correct route won't be the most probable character.
    # This (flaw?) can be exploited by only processing branch patterns like
    #   0000000000000000
    #   ...
    #   0000010000000000
    #   ...
    #   0000000000100000
    #   ...
    #   2000000000000000 a.s.o.
    def go_cheat_brr(self, A, grouped, K, validate, zero_only):
        histogram = self.fsm_histogram(A, grouped[A][1], K)
        for x in range(3 if not zero_only else 1):
            K[A] = histogram[x][0]
            if A == 15:
                if validate(K):
                    return K
            else:
                if not zero_only and x == 0:
                    key = self.go_cheat_brr(A + 1, grouped, K, validate, False)
                else:
                    key = self.go_cheat_brr(A + 1, grouped, K, validate, True)
                if key is not None:
                    return key
        return None

    # get the correct route, used for debugging and analysis
    def route(self, grouped, ex_key):
        opt = []
        for idx, blocks in grouped:
            A = idx - 3
            histogram = self.fsm_histogram(A, blocks, ex_key[:A])
            opt.append([i for i, _ in histogram].index(ex_key[A]))
        return "".join(map(str, opt))


def rc4_fms_handler(assignment, api, _log, case_id):
    """Handler-function for the 'rc4_fms' type"""

    # Note: During testing with some higher difficulty cases, i´ve transferred the implementation to C++17.
    # If you´re interested, you can find the implementation in ../c/main.cpp.
    # The C++ implementation cracks the difficult case in like 100ms (without the cheaty way below).

    # extracted captured_ivs and group them by their corresponding key character index
    grouped = split_blocks(b64decode(assignment["captured_ivs"]), 4)
    grouped.sort(key=lambda b: b[0])
    grouped = [(idx, [*blocks]) for idx, blocks in groupby(grouped, lambda b: b[0])]

    # check if the given key is correct
    def validate(key):
        response = api.post_submission(case_id, {"key": b64encode(key)})
        return response["status"] == "pass"

    k = bytearray(16)
    node = Node(0, grouped, k)

    # try if we can cheat our way through
    res = node.go_cheat_brr(0, grouped, k, validate, False)
    if res is None:
        # if we can't cheat, we have to do it the hard way, i.o.w. search the whole tree
        for _ in range(256):
            # each iteration will increase the search breadth by 1
            # simply re-call the df_bs_search search function
            res = node.df_bs_search(0, grouped, k, validate)
            if res is not None:
                break

    return {
        "key": b64encode(res) if res is not None else "No key found"
    }
