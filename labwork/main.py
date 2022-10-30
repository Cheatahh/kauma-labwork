"""
    Response program (T3INF9004: Cryptanalysis und Method-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)
"""

# stdlib import
import json
import os
import time
from itertools import groupby
from multiprocessing import freeze_support, Manager

# imports
import config
from handlers.cbcKeyEqualsIVHandler import cbc_key_equals_iv_handler
from handlers.gcmBlockToPolyHandler import gcm_block_to_poly_handler
from handlers.gcmMulGF128Handler import gcm_mul_gf2_128_handler
from util.ansiEscape import ansi_red, ansi_reset, ansi_blue, ansi_green, ansi_white
from util.api import LabworkAPI
from util.log import Log
from util.processing import ProcessPool
from util.progressBar import ProgressBar

# import handler functions
from handlers.blockCipherHandler import block_cipher_handler
from handlers.caesarCipherHandler import caesar_cipher_handler
from handlers.histogramHandler import histogram_handler
from handlers.mulGF128Handler import mul_gf_128_handler
from handlers.passwordKeyspaceHandler import password_keyspace_handler
from handlers.pkcs7paddingHandler import pkcs7_padding_handler
from handlers.strcatHandler import strcat_handler

# handler lookup
handlers = {
    "strcat": strcat_handler,
    "histogram": histogram_handler,
    "caesar_cipher": caesar_cipher_handler,
    "password_keyspace": password_keyspace_handler,
    "mul_gf2_128": mul_gf_128_handler,
    "block_cipher": block_cipher_handler,
    "pkcs7_padding": pkcs7_padding_handler,
    "gcm_block_to_poly": gcm_block_to_poly_handler,
    "gcm_mul_gf2_128": gcm_mul_gf2_128_handler,
    "cbc_key_equals_iv": cbc_key_equals_iv_handler
}


# process a single case
# the function will be parallelized by the ProcessPool
def process_case(case_type, case, api, log):
    submit_response = None

    # handle case
    start = time.time()
    try:
        # lookup & run handler for case type
        result = handlers[case_type](case["assignment"], api, log)
        # submit result
        submit_response = api.post_submission(case["tcid"], result)
    except Exception as err:
        result = err
    end = time.time()

    # create log message
    log_msg = "%s------ Result Case #%d '%s' ------%s\n%s%s\n" % (
        ansi_blue, log.identifier, case_type, ansi_reset,
        f'Case: {json.dumps(case, indent=2)}\n' if config.verbosity > 2 else '',
        f'{ansi_red}Error:{ansi_reset} {result}' if isinstance(result, Exception) else
        f'Result: {result}\nTime: {end - start} seconds\nResponse: {submit_response}'
    ) if config.verbosity > 0 else ""

    # update progressbar and set diagnostics
    passed = submit_response["status"] == "pass" if submit_response is not None else False
    log.progress_bar.step(passed, log_msg)


# entry point
if __name__ == "__main__":

    print(f"{ansi_white}{config.name}\n{ansi_blue}------ CONFIG ------{ansi_reset}\n{json.dumps(vars(config.config), indent=2)}")

    # enable freeze support, e.g. allow the current process to be unresponsive during child process creation
    freeze_support()

    # handshake with API & prepare http requests
    with LabworkAPI(config.config) as labwork_api:

        # get current assignment
        assignments = labwork_api.get_assignments()
        if config.debug:
            with open(f"{config.labwork_id}.json", "w") as file:
                json.dump(assignments, file, indent=2)

        # group testcases by type
        testcases = [(case_type, [*cases]) for case_type, cases in
                     groupby(assignments["testcases"], lambda case: case["type"])]
        max_case_type = max(len(case_type) for case_type, _ in testcases)

        # init process pool
        results = []
        with ProcessPool(config.process_count) as pool:

            # manage shared variables between processes
            manager = Manager()

            try:
                # process each case type
                for case_type, cases in testcases:
                    # create progressbar
                    progressbar = ProgressBar(case_type, max_case_type + 1, 20, len(cases),
                                              config.verbosity, manager)

                    # run function 'process_case' with each case in the process pool
                    req_time, _ = pool.run(process_case, ((case_type, case, labwork_api, Log(identifier, progressbar))
                                                          for identifier, case in enumerate(cases)), progressbar)

                    # finish progressbar for case type and append results
                    progressbar.finish()
                    results.append((case_type, progressbar.passed.value, progressbar.max_value, req_time))

            except KeyboardInterrupt:
                print("Interrupted by user :(")
                # noinspection PyUnresolvedReferences, PyProtectedMember
                # bad practice, but we need to terminate the child processes somehow
                os._exit(1)

    # print conclusion
    if config.verbosity > 0:
        print(f"{ansi_blue}------ CONCLUSION '{config.labwork_id}' ------{ansi_reset}")
        total_cases = sum(total for _, _, total, _ in results)
        passed_cases = sum(passed for _, passed, _, _ in results)
        print(f"Total Cases: {total_cases}\nPassed Cases: {passed_cases}")
        for case_type, passed, total, total_time in results:
            print(f"\t'{case_type}': {passed}/{total} in {total_time} seconds")
        print(f"""{f'{ansi_green}PASSED' if total_cases == passed_cases else f'{ansi_red}FAILED'}{ansi_reset} in {
        sum(total_time for _, _, _, total_time in results)} seconds (with waiting & printing)""")
