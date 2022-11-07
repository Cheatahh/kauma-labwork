"""
    This file is a handler module for response program (T3INF9004: Cryptanalysis und Method-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)
    Component: Labwork06

    Functions:

    chi_square_handler
"""

from util.functions import b64decode, b64encode

critical_values = {
    0.1: (227, 285),
    0.05: (219, 294),
    0.01: (205, 311),
    0.001: (191, 331),
    0.0001: (179, 348),
}


def decimate(data, selector):
    offset = selector.get("offset", 0)
    stride = selector.get("stride", 1)
    return bytes(data[base + offset] for base in range(0, len(data), stride))


def action_decimate(data, selectors):
    result = []
    for selector in selectors:
        value = decimate(data, selector)
        result.append({
            "decimated_data": b64encode(value)
        })
    return result


def action_histogram(data, selectors):
    result = []
    for selector in selectors:
        value = decimate(data, selector)
        keys = {*value}
        result.append({
            "histogram": {key: value.count(key) for key in keys}
        })
    return result


def action_chi_square(data, selectors):
    result = []
    for selector in selectors:
        value = decimate(data, selector)
        n = len(value)  # number of samples
        m = 256         # degrees of freedom

        # we don't really care about the actual values, just the counts
        # take all occurrences in account, even if it's zero
        histogram = [value.count(key) for key in range(m)]

        S = (m / n) * sum((t - n / m) ** 2 for t in histogram)
        Cl, Cr = critical_values[0.01]  # critical_values[selector["alpha"]]

        result.append({
            "chi_square_statistic": round(S),
            "verdict": "no_result" if Cl <= S <= Cr else "uniform" if S < Cl else "non_uniform"
        })
    return result


actions = {
    "decimate": action_decimate,
    "histogram": action_histogram,
    "chi_square": action_chi_square
}


def chi_square_handler(assignment, _api, _log, _case_id):
    """Handler-function for the 'chi_square' type"""

    # extract values
    action = assignment["action"]
    data = b64decode(assignment["data"])
    selectors = assignment["selectors"]

    return actions[action](data, selectors)
