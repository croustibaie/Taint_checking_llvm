#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/CommandLine.h"

#include "taint.h"
#include "taint_visitor.h"
#include "instr_taintgrind.h"
#include "dump.h"

using namespace llvm;

namespace TaintAnalysis {
    struct ASBDetection : public ModulePass {
        static char ID;
        static cl::opt<bool> optionDumpTaint;
        static cl::opt<bool> optionCheckTaint;
        static cl::opt<bool> optionInstrumentOnly;
        static cl::opt<int> optionLogLevel;

        ASBDetection() : ModulePass(ID) {}

        virtual bool runOnModule(Module &M) {
            if (optionInstrumentOnly) {
                InstrTaintgrindVisitor instrv(optionLogLevel);
                return instrv.instrumentModule(M);
            }
            
            bool taintChanged = true;
            TaintVisitor vis;
            
            while (taintChanged) {
                taintChanged = vis.taintModule(M);
                // errs() << "--------------------------------------------------------------------------------\n\n";
            }

            if (optionDumpTaint) {
                // dump the final taint results
                DumpTaintVisitor dumper(optionLogLevel, vis);
                dumper.visit(M);
                // the module was not modified -> return false
                return false;
            }

            // the module was not modified -> return false
            return false;
        }
    };

    cl::opt<bool> ASBDetection::optionDumpTaint("asb_detection_dump_taint", cl::desc("Dump the statically analysed taint information"));
    cl::opt<bool> ASBDetection::optionCheckTaint("asb_detection_check_taint", cl::desc("Check the static taint but do not instrument"));
    cl::opt<bool> ASBDetection::optionInstrumentOnly("asb_detection_instr_only", cl::desc("Only instrument but don't run static checks"));
    cl::opt<int> ASBDetection::optionLogLevel("asb-log-level", cl::desc("Specifiy the log level; everything <= will be logged (0-100)"),
                                              cl::value_desc("level"), cl::init(10));
    
    char ASBDetection::ID = 0;
    static RegisterPass<ASBDetection> X("asb_detection", "test function exist", false, false);
}
