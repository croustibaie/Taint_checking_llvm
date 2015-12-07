"""
tests.py for semantic analysis tests
"""

# import the test infrastructure
from infrastructure.tests import make_tests
import os

optionals = []

def allTests():
    """
    This function returns a list of tests.
    """
    tests = make_tests("static-taint", True)
    
    # mark optionals
    for test in tests:
        if test.getName() in optionals:
            test.opt()
    
    return tests

