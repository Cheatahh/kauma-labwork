"""
    This file is a handler module for response program (T3INF9004: Kryptoanalyse und Methoden-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)

    Functions:

    password_keyspace_handler
"""
from functools import reduce
from itertools import product
from string import ascii_lowercase, ascii_uppercase, digits


# This function contains multiple approaches to solve this problem, see comments for detail
def password_keyspace_handler(assignment, session):
    """Handler-function for the 'password_keyspace' type."""

    return 0

    # shortcut and safety
    length = assignment["length"]
    if length <= 0:
        return 0

    # extract special chars from alphabet, do not have to rely on presets
    special_chars = "".join({*assignment["alphabet"]} - {*(ascii_lowercase + ascii_uppercase + digits)})

    # generate all possible strings of length 'length' by
    possibilities = ["".join(item) for item in product(assignment["alphabet"], repeat=length)]

    # test if a possible value is failing a given restriction
    # hashtable lookup => faster, see another version down below
    """
    is_failing_restriction = {
        "at_least_one_special_char":
            # not any = none
            # if no char is a special char -> fail
            lambda value: not any(char in special_chars for char in value),
        "at_least_one_uppercase_char":
            # if no char is uppercase -> fail
            lambda value: not any(char.isupper() for char in value),
        "at_least_one_lowercase_char":
            # if no char is lowercase -> fail
            lambda value: not any(char.islower() for char in value),
        "at_least_one_digit":
            # if no char is a digit -> fail
            lambda value: not any(char.isdigit() for char in value),
        "no_consecutive_same_char":
            # iterate over each index (except last char, 0 <= index < length - 1)
            # compare current char and next char
            # if there are any consecutive chars -> fail
            lambda value: any(char == value[index + 1] for index, char in enumerate(value[:-1])),
        "special_char_not_last_place":
            # if last char is special char -> fail
            lambda value: value[-1] in special_chars
    }
    """

    # slower, but more robust version of 'is_failing_restriction'
    """
    def is_failing_restriction(restriction, value):
        match restriction:
            case "at_least_one_special_char":
                return not any(char in special_chars for char in value)
            case "at_least_one_uppercase_char":
                return not any(char.isupper() for char in value)
            case "at_least_one_lowercase_char":
                return not any(char.islower() for char in value)
            case "at_least_one_digit":
                return not any(char.isdigit() for char in value)
            case "no_consecutive_same_char":
                return any(char == value[index + 1] for index, char in enumerate(value[:-1]))
            case "special_char_not_last_place":
                return value[-1] in special_chars 
    """

    # initial approach, count all possible strings passing all restrictions
    """
    count = 0
    for possibility in possibilities:
        # not any = none; if no restrictions fail -> pass
        if not any(is_failing_restriction[restriction](possibility) for restriction in assignment["restrictions"]):
            count += 1
            
    return {
        "count": count
    }
    """

    def filter_by_restriction(values, res):
        match res:
            case "at_least_one_special_char":
                # if any char is a special char -> pass filter
                return filter(lambda value: any(char in special_chars for char in value), values)
            case "at_least_one_uppercase_char":
                # if any char is uppercase -> pass filter
                return filter(lambda value: any(char.isupper() for char in value), values)
            case "at_least_one_lowercase_char":
                # if any char is lowercase -> pass filter
                return filter(lambda value: any(char.islower() for char in value), values)
            case "at_least_one_digit":
                # if any char a digit -> pass filter
                return filter(lambda value: any(char.isdigit() for char in value), values)
            case "no_consecutive_same_char":
                # iterate over each index (except last char, 0 <= index < length - 1)
                # compare current char and next char
                # if there are [not any] = [none] consecutive chars -> pass filter
                return filter(lambda value: not any(char == value[index + 1] for index, char in enumerate(value[:-1])),
                              values)
            case "special_char_not_last_place":
                # if last char is not a special char -> pass filter
                return filter(lambda value: value[-1] not in special_chars, values)

    # second approach, filter possibilities with restrictions
    # seems to be ~30% faster, memory usage stays the same
    """
    for restriction in assignment["restrictions"]:
        possibilities = filter_by_restriction(restriction, possibilities)
    """

    # using second approach
    # using reduce seems to be even faster (~7%)!?
    # noinspection PyTypeChecker
    possibilities = reduce(filter_by_restriction, assignment["restrictions"], possibilities)

    return {
        "count": len([*possibilities])
    }
