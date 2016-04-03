"""
tests.py for dynamic taint analysis tests
"""

# import the test infrastructure
from infrastructure.tests import make_tests
import os

optionals = []

def allTests():
    """
    This function returns a list of tests.
    """
    tests = make_tests("instr_aop", "../dynalize.sh", True, ["--no-color"])
    
    for test in tests:
        # mark optionals
        if test.getName() in optionals:
            test.opt()

        test.timeoutFactor = 3
            
    return tests

