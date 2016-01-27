'''
Created on 8 Dec 2013

@author: Alexander Kampmann, David Poetzsch-Heffter
'''

import sys, os, difflib, shutil, imp, tempfile
from timed_process import CompileProcess, RuntimeProcess
from valgrindxml import ValgrindXML

class Test(object):
    """Superclass for all the tests."""
    optional = False
        
    def __init__(self, exe, base, src, options, optional=False):
        self.exe = exe
        self.basedir = base
        self.srcfile = src
        self.options = options
        self.optional = optional
        self.timeoutFactor = 1
    
    def opt(self):
        self.optional = True
        return self
        
    def isOptional(self):
        return self.optional
    
    def getName(self):
        return os.path.join(self.basedir, self.srcfile)

    def execCmd(self):
        return [os.path.abspath(self.exe)] + self.options + [self.srcfile]
    
    def fail(self, msg=""):
        print("[FAIL] " + " ".join(self.execCmd()))
        print(msg)
        return False

    def invoke(self):
        timeout = CompileProcess.timeout * self.timeoutFactor
            
        p = CompileProcess(self.execCmd(), self.basedir, timeout)
        p.execute()
        return self.check(p)
        
    def check(self, proc):
        cmd = os.path.basename(proc.cmd[0])
        
        if proc.killed:
            return self.fail("  Process '%s' timed out.\n\n" % cmd)
                    
        if proc.crash():
            return self.fail("  '%s' crashed. Return code was: %d\n\n" % (cmd, proc.returncode))
                    
        return True

class ValgrindTest(Test):
    """Auto-check for memory leaks with valgrind"""
    
    VALGRIND_XML_FILE = os.path.join(tempfile.gettempdir(), "impala_valgrind.xml")
        
    def __init__(self, test):
        super(ValgrindTest, self).__init__(test.exe, test.basedir, test.srcfile, test.options, test.isOptional())
        self.timeoutFactor = 5

    def execCmd(self):
        return ["valgrind", "--xml=yes", "--xml-file="+ValgrindTest.VALGRIND_XML_FILE] + \
            [os.path.abspath(self.exe)] + self.options + [self.srcfile]
        
    def check(self, p):
        if not super(ValgrindTest, self).check(p):
            return False
        
        try:
            vgout = ValgrindXML(ValgrindTest.VALGRIND_XML_FILE)

            success = len(vgout.leaks) == 0

            if not success:
                return self.fail("\n" + vgout)
            else:
                return True
        except Exception as e:
            print "Parsing valgrind output FAILED: %s" % e
            return False

def diff_output(output, expected):
    olines = output.splitlines(1)
    elines = expected.splitlines(1)
    
    diff = difflib.Differ()
    fails = 0
    for cp in diff.compare(elines, olines):
        if cp.startswith('-') or cp.startswith('+'):
            print(cp.rstrip())
            fails=fails+1
    
    return True if fails == 0 else False

class CompilerOutputTest(Test):
    """Superclass tests which work on a single file and compare the output."""
    positive = True
    basedir = "."
    srcfile = ""
    options = []
    result = None
    
    def __init__(self, positive, exe, base, src, res, options=[]):
        super(CompilerOutputTest, self).__init__(exe, base, src, list(options))
        self.positive = positive
        self.result = res
    
    def check(self, p):
        if not super(CompilerOutputTest, self).check(p):
            return False
        
        if p.success() != self.positive:
            return self.fail("Output: %s\n\n" % p.output)
                    
        if self.result is None:
            return True
    
        with open(os.path.join(self.basedir, self.result), 'r') as f:
            return diff_output(p.output.strip(), f.read().strip())

def get_tests(directory):
    """A generator for test files based on the .ll files in directory
    
    Output files are expected to have the same name but with .output extension.
    If no output file is found for a test no output is assumed.
    
    This yields (test_file, output_file) for each .ll file in the directory"""
    tests = []

    for testfile in os.listdir(directory):
        if os.path.splitext(testfile)[1] == ".ll":
            of = os.path.splitext(testfile)[0] + ".output"
            res = of if os.path.exists(os.path.join(directory, of)) else None
            yield (testfile, res)

def make_compiler_output_tests(directory, exe, positive=True, options=[]):
    """Creates a list of CompilerOutputTests using get_tests(directory)"""
    tests = []
    for testfile, res in get_tests(directory):
        tests.append(CompilerOutputTest(positive, exe, directory, testfile, res, options))
    return sorted(tests, key=lambda test: test.getName())

make_tests = make_compiler_output_tests

def get_tests_from_dir(directory):
    testfile = os.path.join(directory, "tests.py")
    
    if os.path.exists(testfile):
        tests = imp.load_source("tests", testfile).allTests()
    else:
        tests = make_tests(directory)
    return tests

def executeTests(tests):
    """Invoke this function with a list of test objects to run the tests. """
    
    res = {}
    s   = True
    for i in range(len(tests)):
        print ("["+str(i+1)+"/"+str(len(tests))+"] " + tests[i].getName())
        res[tests[i]] = s = tests[i].invoke()

    print("\n* Test summary\n")
    failOpt = 0
    failReq = 0
    
    opt_tests = []
    req_tests = []
    for t in tests:
        opt_tests.append(t) if t.isOptional() else req_tests.append(t)
    
    for t in req_tests:
        if not res[t]:
            print("- REQUIRED test failed: "+t.getName())
            failReq += 1
            
    for t in opt_tests:
        if not res[t]:
            print("- OPTIONAL test failed: "+t.getName())
            failOpt += 1
    
    if failOpt == 0 and failReq == 0:
        print("\n* All " + str(len(tests)) +  " tests were successful.")
    else:
        if failReq == 0:
            print("\n* All %i required tests were successful." % len(req_tests))
        else:
            print("\n!" + str(failReq) + " of " + str(len(req_tests)) + " REQUIRED tests failed.")
        if failOpt == 0:
            print("\n* All %i optional tests were successful." % len(opt_tests))
        else:
            print("\n!" + str(failOpt) + " of " + str(len(opt_tests)) + " OPTIONAL tests failed.")
