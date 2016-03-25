#!/usr/bin/env python

"""Usage: run_tests.py [options] [subdirectory that contains test cases]

If no subdirectory is given '.' is assumed.

Command line options:
 -e, --executable <Path to executable>
     Default is 'impala' (if possible) or '../build/bin/impala' otherwise;
     on Windows '.exe' is appended
 -t, --timeout <floating point value in seconds>
     Default is 1.0
 -j, --jobs <processes>
     Default is 4
 -L, --valgrind
     Use valgrind to check for memory leaks during testing
"""

import infrastructure.tests
from infrastructure.timed_process import TimedProcess
import os, sys, getopt, subprocess

def invoke(directory, processes, valgrind):
    os.system("make -C '%s' -j %d all" % (directory, processes))
    print("-" * 80)
        
    tests = infrastructure.tests.get_tests_from_dir(directory)
    
    if valgrind:
        tests = [infrastructure.tests.ValgrindTest(t) for t in tests]
    
    infrastructure.tests.executeTests(tests, processes)

def get_executable():
    return os.path.join(".", "asbdetect.sh")
    
def main():
    valgrind = False
    processes = 4
    
    # get cmd file
    try:
        opts, args = getopt.getopt(sys.argv[1:], "he:t:j:L", ["help", "executable", "timeout", "jobs", "valgrind"])
    except getopt.error as msg:
        print(msg)
        sys.exit(2)
    
    # handle options
    for o, a in opts:
        if o in ("-h", "--help"):
            print(__doc__)
            sys.exit(0)
        if o in ("-t", "--timeout"):
            TimedProcess.timeout = float(a)
        if o in ("-L", "--valgrind"):
            valgrind = True
        if o in ("-j", ):
            processes = int(a)

    if len(args) > 1:
        print("You specified too many arguments.")
        print(__doc__)
        sys.exit(2)
    elif len(args) == 0:
        print("You did not specify a test directory. Using '.'")
        directory = "."
    else:
        directory = args[0]

    invoke(directory, processes, valgrind)

main()
