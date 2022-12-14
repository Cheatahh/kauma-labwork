"""
    This file is a handler module for response program (T3INF9004: Cryptanalysis und Method-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)
    Component: Labwork01

    Functions:

    strcat_handler
"""


def strcat_handler(assignment, _api, _log, _case_id):
    """Handler-function for the 'strcat' type"""

    parts = assignment["parts"]

    # join all parts with a whitespace as separator
    return " ".join(parts)
