#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"

#include "taint.h"
#include "taint_visitor.h"
#include "dump.h"

using namespace llvm;

namespace TaintAnalysis {
    struct bishe_insert : public ModulePass {
        static char ID;  

        bishe_insert() : ModulePass(ID) {}

        virtual bool runOnModule(Module &M) {
            bool taintChanged = true;
            TaintVisitor vis;
            
            while (taintChanged) {
                taintChanged = vis.taintModule(M);
                // errs() << "--------------------------------------------------------------------------------\n\n";
            }

            // dump the final taint results
            DumpTaintVisitor dumper(10, vis);
            dumper.visit(M);
            
            // the module was not modified -> return false
            return false;
        }
    };

    char bishe_insert::ID = 0;
    static RegisterPass<bishe_insert> X("bishe_insert", "test function exist", false, false);
}
