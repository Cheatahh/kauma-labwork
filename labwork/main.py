#!/usr/bin/python3
"""
    Response program for the exercise in T3INF9004: Kryptoanalyse und Methoden-Audit.

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)
"""

import json
import sys

import requests

# import handler functions
from caesarCipherHandler import caesar_cipher_handler
from histogramHandler import histogram_handler
from strcatHandler import strcat_handler

# handler lookup
handlers = {
    "strcat": strcat_handler,
    "histogram": histogram_handler,
    "caesar_cipher": caesar_cipher_handler
}

# setup config from system args
if len(sys.argv) != 4:
    print("Usage: <endpoint> <client-id> <assignment>")
    exit(1)

endpoint = sys.argv[1]
client_id = sys.argv[2]
labwork = sys.argv[3]

request_headers = {"Accept": "application/json", "Content-Type": "application/json"}

# print config
print("------ CONFIG ------")
print("Endpoint:", endpoint)
print("Client ID:", client_id)
print("Assignment Name:", labwork)

# get assigment
assignments_response = requests.get(endpoint + "/assignment/" + client_id + "/" + labwork,
                                    headers=request_headers)
assert assignments_response.status_code == 200
assignments = assignments_response.json()

print("Assignment Header:", json.dumps(dict(filter(
    lambda pack: pack[0] != "testcases", assignments.items())), indent=2))

# get cases
testcases = assignments["testcases"]

# setup diagnostics
total_sample_solutions = 0
passed_sample_solutions = 0
total_cases = len(testcases)
passed_cases = 0

# process cases
for testcase in testcases:

    # get case type
    case_type = testcase["type"]
    print("------ NEW CASE ------")
    print("Case:", json.dumps(testcase, indent=2))

    try:
        # lookup & run handler for case type
        result = handlers[case_type](testcase["assignment"])
        print("Result:", result)

        # local test for expected solutions
        if "expect_solution" in testcase:
            total_sample_solutions += 1
            match = result == testcase["expect_solution"]
            print("Matches expectation (local):", match)
            if match:
                passed_sample_solutions += 1

        # submit result
        submit_result_response = requests.post(endpoint + "/submission/" + testcase["tcid"],
                                               headers=request_headers, json=result)
        assert submit_result_response.status_code == 200
        submit_result = submit_result_response.json()
        print("Submit Result:", submit_result)

        if submit_result["status"] == "pass":
            passed_cases += 1

    except KeyError:
        print("Error: Could not match type", case_type)

# print diagnostics conclusion
print("------ CONCLUSION ------")
print("Total sample solutions:", total_sample_solutions)
print("Passed sample solutions:", passed_sample_solutions,
      "[{:.0%}]".format(float(passed_sample_solutions) / float(total_sample_solutions)))
print("Total cases:", total_cases)
print("Passed cases:", passed_cases,
      "[{:.0%}]".format(float(passed_cases) / float(total_cases)))
