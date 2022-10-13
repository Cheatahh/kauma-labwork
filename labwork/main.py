"""
    Response program for the exercise in T3INF9004: Cryptanalyses und Method-Audit.

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)
"""

import json
import time

from api import API
# import handler functions
from blockCipherHandler import block_cipher_handler
from caesarCipherHandler import caesar_cipher_handler
from histogramHandler import histogram_handler
from mulGF128Handler import mul_gf_128_handler
from passwordKeyspaceHandler import password_keyspace_handler
from strcatHandler import strcat_handler

# handler lookup
handlers = {
    "strcat": strcat_handler,
    "histogram": histogram_handler,
    "caesar_cipher": caesar_cipher_handler,
    "password_keyspace": password_keyspace_handler,
    "mul_gf2_128": mul_gf_128_handler,
    "block_cipher": block_cipher_handler
}

with API() as api:

    # get assigment
    assignments = api.get_assignments()

    print("Assignment Header:", json.dumps(dict(filter(
        lambda pack: pack[0] != "testcases", assignments.items())), indent=2))

    # setup diagnostics
    total_time = {}

    total_sample_solutions = {}
    passed_sample_solutions = {}

    total_cases = {}
    passed_cases = {}

    # process cases
    for testcase in assignments["testcases"]:

        # get case type
        case_type = testcase["type"]
        print("------ NEW CASE ------")
        print("Case:", json.dumps(testcase, indent=2))

        # diagnostics (cases)
        if case_type in total_cases:
            total_cases[case_type] += 1
        else:
            total_cases[case_type] = 1
            passed_cases[case_type] = 0
            total_time[case_type] = 0

        try:
            # lookup & run handler for case type
            start = time.process_time()
            result = handlers[case_type](testcase["assignment"], api)
            end = time.process_time()
            print("Result:", result, "in", end - start, "seconds")
            total_time[case_type] += end - start

            # local test for expected solutions
            if "expect_solution" in testcase:

                # diagnostics (testcases)
                if case_type in total_sample_solutions:
                    total_sample_solutions[case_type] += 1
                else:
                    total_sample_solutions[case_type] = 1
                    passed_sample_solutions[case_type] = 0

                match = result == testcase["expect_solution"]
                print("Matches expectation (local):", match)

                if match:
                    passed_sample_solutions[case_type] += 1

            # submit result
            submit_result = api.post_submission(testcase["tcid"], result)
            print("Submit Result:", submit_result)

            if submit_result["status"] == "pass":
                passed_cases[case_type] += 1

        except KeyError:
            print("Error: Could not match type", case_type)

        except ValueError as err:
            print("Error:", err)

        except AssertionError as err:
            print("Error:", err)

# print diagnostics conclusion
print("------ CONCLUSION ------")

print("Total sample solutions:", sum(total_sample_solutions.values()))
print("Passed sample solutions:")
for case_type, passes in passed_sample_solutions.items():
    # pretty print
    print("\t'{case_type}' {passes} of {total} [{percent:.0%}]".format(
        case_type=case_type, passes=passes, total=total_sample_solutions[case_type],
        percent=float(passes) / float(total_sample_solutions[case_type]))
    )

print("Total cases:", sum(total_cases.values()))
print("Passed cases:")
for case_type, passes in passed_cases.items():
    # pretty print
    print("\t'{case_type}' {passes} of {total} [{percent:.0%}] in {seconds} seconds".format(
        case_type=case_type, passes=passes, total=total_cases[case_type],
        percent=float(passes) / float(total_cases[case_type]),
        seconds=total_time[case_type]
    ))
