"""
    Response program for the exercise in T3INF9004: Cryptanalysis und Method-Audit.

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)
"""
import json
import threading
import time

# import handler functions
from handlers.blockCipherHandler import block_cipher_handler
from handlers.caesarCipherHandler import caesar_cipher_handler
from handlers.histogramHandler import histogram_handler
from handlers.mulGF128Handler import mul_gf_128_handler
from handlers.passwordKeyspaceHandler import password_keyspace_handler
from handlers.pkcs7paddingHandler import pkcs7_padding_handler
from handlers.strcatHandler import strcat_handler
from util.api import API, labwork, verbosity, threads_count
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

if verbosity > 2:
    print("Assignment Header:", json.dumps(dict(filter(
        lambda key: key[0] != "testcases", assignments.items())), indent=2))

# group testcases by type
testcases = assignments["testcases"]
testcases = {case_type: [
    (_id, _case) for _id, _case in enumerate(testcases) if _case["type"] == case_type] for case_type in
    {testcase["type"] for testcase in testcases}
}
max_type_chars = max(len(case_type) for case_type in testcases)

results = []
# process each case type
for case_type, cases in testcases.items():
    # setup diagnostics & processbar
    progress = ProgressBar(case_type, max_type_chars - len(case_type), len(cases), verbosity)

    # function to parallelize
    def process_cases(assigned_cases):

        # create thread-local session
        with API() as _api:

            # process each case
            for _id, case in assigned_cases:

                submit_response = None

                if verbosity > 0:
                    progress.update("------ Processing Case #%d, '%s' ------\n" % (_id, case_type))

                # handle case
                _start = time.time()
                try:
                    # lookup & run handler for case type
                    result = handlers[case_type](_id, case["assignment"], _api, progress)
                    submit_response = _api.post_submission(case["tcid"], result)
                except Exception as err:
                    result = err
                _end = time.time()

                # create log message
                logMessage = "------ Result Case #%d, '%s' ------\n%s%s\n" % (
                    _id, case_type, "Case: %s\n" % (json.dumps(case, indent=2)) if verbosity > 2 else "",
                    "Result: %s\nTime: %s seconds\nResponse: %s" % (result, _end - _start, submit_response)
                    if not isinstance(result, Exception) else "Error: %s" % result
                ) if verbosity > 0 else ""
                passed = submit_response["status"] == "pass" if submit_response is not None else False

                # update processbar
                progress.step(logMessage, passed)

    # process each case
    cases = [[case for index, case in enumerate(cases) if index % threads_count == active]
             for active in range(threads_count)]

    # create threads
    threads = [threading.Thread(target=process_cases, args=(assigned_cases,)) for assigned_cases in cases]

    # start all threads, go brrrr
    for thread in threads:
        thread.start()

    # wait for all threads
    start = time.time()
    for thread in threads:
        thread.join()
    end = time.time()
    print("%s seconds" % (end - start))

    progress.finish()

    # add case results
    results.append((case_type, progress.passed, progress.total, end - start))

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
