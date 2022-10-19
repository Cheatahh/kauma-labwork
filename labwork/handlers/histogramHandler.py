"""
    This file is a handler module for response program (T3INF9004: Cryptanalyses und Method-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)
    Component: Labwork01

    Functions:

    histogram_handler
"""


def histogram_handler(assignment, _0, _1):
    """Handler-function for the 'histogram' type"""

    text = assignment["text"]

    # spread all chars into a set (eliminate multiple occurrences for iteration)
    charset = {*text}

    # generate dictionary by mapping each char to its occurrence in the given text
    return {x: text.count(x) for x in charset}
