"""
tests.py for dynamic taint analysis tests
"""

# import the test infrastructure
from infrastructure.tests import make_tests
import os
from os.path import splitext, basename

optionals = ["deref06"]

def allTests():
    """
    This function returns a list of tests.
    """
    tests = make_tests("instr_mem", "../dynalize.sh", True, ["--no-color"])
    
    for test in tests:
        # mark optionals
        if basename(splitext(splitext(test.getName())[0])[0]) in optionals:
            test.opt()

        test.timeoutFactor = 3
            
    return tests

