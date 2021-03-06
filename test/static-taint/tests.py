"""
tests.py for static taint analysis tests
"""

# import the test infrastructure
from infrastructure.tests import make_tests
import os

optionals = []

def allTests():
    """
    This function returns a list of tests.
    """
    tests = make_tests("static-taint", "show-taint.sh", True)
    
    for test in tests:
        # mark optionals
        if test.getName() in optionals:
            test.opt()
    
    return tests

