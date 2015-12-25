#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/CommandLine.h"

#include "taint.h"
#include "taint_visitor.h"
#include "dump.h"

using namespace llvm;

namespace TaintAnalysis {
    struct ASBDetection : public ModulePass {
        static char ID;
        static cl::opt<bool> optionDumpTaint;
        static cl::opt<bool> optionCheckTaint;

        ASBDetection() : ModulePass(ID) {}

        virtual bool runOnModule(Module &M) {
            bool taintChanged = true;
            TaintVisitor vis;
            
            while (taintChanged) {
                taintChanged = vis.taintModule(M);
                // errs() << "--------------------------------------------------------------------------------\n\n";
            }

            if (optionDumpTaint) {
                // dump the final taint results
                DumpTaintVisitor dumper(10, vis);
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
    
    char ASBDetection::ID = 0;
    static RegisterPass<ASBDetection> X("asb_detection", "test function exist", false, false);
}
