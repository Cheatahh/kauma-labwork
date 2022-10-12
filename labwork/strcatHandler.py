"""
    This file is a handler module for response program (T3INF9004: Kryptoanalyse und Methoden-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)

    Functions:

    strcat_handler
"""


def strcat_handler(assignment, session):
    """Handler-function for the 'strcat' type"""

    parts = assignment["parts"]

    # join all parts with a whitespace as separator
    return " ".join(parts)
