#ifndef TAINT_ANALYSIS_DUMP_H
#define TAINT_ANALYSIS_DUMP_H

#include "taint.h"
#include "taint_visitor.h"

namespace TaintAnalysis {
    class DumpTaintVisitor : public InstVisitor<DumpTaintVisitor> {
      private:
        int verbosity;
        TaintVisitor& taintData;
        
      public:
        DumpTaintVisitor(TaintVisitor& tv) : verbosity(10), taintData(tv) {}
        DumpTaintVisitor(int verbosity, TaintVisitor& tv) : verbosity(verbosity), taintData(tv) {}
        
        void visitDbgDeclareInst(DbgDeclareInst &I)    { /* do nothing */ }
        void visitDbgValueInst(DbgValueInst &I)        { /* do nothing */ }
        void visitDbgInfoIntrinsic(DbgInfoIntrinsic &I) { /* do nothing */ }
        
        void visitInstruction(Instruction& instr) {
            if (verbosity >= 10) {
                instr.print(errs());
                errs() << "    -> ";
                taintData.getTaint(&instr).dump(errs());
                errs() << "\n";
            }

            if (verbosity >= 20) { // print argument taints
                errs() << "  :\n";

                for (int i = 0; i < instr.getNumOperands(); ++i) {
                    Value *op = instr.getOperand(i);
                    errs() << "    ";
                    op->printAsOperand(errs());
                
                    if (isa<Constant>(op)) {
                        errs() << " :: CONSTANT -> TAINT_NONE";
                        errs() << "\n";
                    } else if (isa<Instruction>(op)) {
                        errs() << " :: INSTRUCTION -> ";
                        taintData.getTaint(dyn_cast<Instruction>(op)).dump(errs());
                        errs() << "\n";
                    } else if (isa<Argument>(op)) {
                        errs() << " :: ARGUMENT -> TAINT_MAYBE";
                        errs() << "\n";
                    } else if (!isa<MetadataAsValue>(op)) {
                        assert(false); // NOT IMPLEMENTED
                    }
                }

                errs() << "\n";
            }
//            if (inst.getDebugLoc())
//                errs() << inst.getDebugLoc().getLine();
        }

        /// @return true if the taint for this function changed
        void visitFunction(Function& f) {
            if (verbosity >= 5) {
                if (verbosity >= 10) {
                    errs() << "\n";
                }
                
                // print function header
                f.getReturnType()->print(errs());
                errs() << " " << f.getName() << "(";
            
                std::string sep("");
                const Function::ArgumentListType& argList = f.getArgumentList();
                for (Function::ArgumentListType::const_iterator it = argList.begin(); it != argList.end(); ++it) {
                    errs() << sep;
                    it->print(errs());
                    sep = ", ";
                }
                
                errs() << "):    -> ";
                taintData.getTaint(&f).dump(errs());
                errs() << "\n";
            }
        }
    };
}

#endif
