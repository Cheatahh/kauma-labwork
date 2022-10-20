"""
    Response program for the exercise in T3INF9004: Cryptanalysis und Method-Audit.

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)
"""

import json
import time

# import handler functions
from handlers.blockCipherHandler import block_cipher_handler
from handlers.caesarCipherHandler import caesar_cipher_handler
from handlers.histogramHandler import histogram_handler
from handlers.mulGF128Handler import mul_gf_128_handler
from handlers.passwordKeyspaceHandler import password_keyspace_handler
from handlers.pkcs7paddingHandler import pkcs7_padding_handler
from handlers.strcatHandler import strcat_handler
from util.api import API, labwork, verbosity
from util.progressBar import ProgressBar

# handler lookup
handlers = {
    "strcat": strcat_handler,
    "histogram": histogram_handler,
    "caesar_cipher": caesar_cipher_handler,
    "password_keyspace": password_keyspace_handler,
    "mul_gf2_128": mul_gf_128_handler,
    "block_cipher": block_cipher_handler,
    "pkcs7_padding": pkcs7_padding_handler
}

with API() as api:
    # get assigment
    assignments = api.get_assignments()
    testcases = assignments["testcases"]

    if verbosity > 2:
        print("Assignment Header:", json.dumps(dict(filter(
            lambda key: key[0] != "testcases", assignments.items())), indent=2))

    # group testcases by type
    testcases = {case_type: [
        *filter(lambda _case: _case["type"] == case_type, testcases)] for case_type in
        {testcase["type"] for testcase in testcases}
    }
    max_type_chars = max(len(case_type) for case_type in testcases)

    results = []
    # process each case type
    for case_type, cases in testcases.items():

        # setup diagnostics & processbar
        progress = ProgressBar(case_type, max_type_chars - len(case_type), len(cases), verbosity)
        total_time = 0

        # process each case
        for case in cases:

            result = None
            submit_response = None

            if verbosity > 0:
                progress.update("------ NEW CASE, '%s' ------\n" % case_type)

            # handle case
            start = time.time()
            try:
                # lookup & run handler for case type
                result = handlers[case_type](0, case["assignment"], api, progress)
                submit_response = api.post_submission(case["tcid"], result)
            except Exception as err:
                result = err
            end = time.time()

            # create log message
            logMessage = "%s%s\n" % (
                "Case: %s\n" % (json.dumps(case, indent=2)) if verbosity > 2 else "",
                "Result: %s\nTime: %s seconds\nResponse: %s" % (result, end - start, submit_response)
                if not isinstance(result, Exception) else "Error: %s" % result
            ) if verbosity > 0 else ""
            passed = submit_response["status"] == "pass" if submit_response is not None else False

            # update processbar
            progress.step(logMessage, passed)
            total_time += end - start

        progress.finish()

        # add case results
        results.append((case_type, progress.passed, progress.total, total_time))

# print debug info
if verbosity > 0:
    print("------ CONCLUSION", labwork, "------")
    total_cases = sum(total for _, _, total, _ in results)
    passed_cases = sum(passed for _, passed, _, _ in results)
    print("Total Cases:", total_cases)
    print("Passed Cases:", passed_cases)
    for case_type, passed, total, total_time in results:
        print("\t'%s': %d/%d in %f seconds" % (case_type, passed, total, total_time))

    print("%s in %f seconds (with waiting & printing)" % ("PASSED" if total_cases == passed_cases else "FAILED",
                                                          sum(total_time for _, _, _, total_time in results)))
