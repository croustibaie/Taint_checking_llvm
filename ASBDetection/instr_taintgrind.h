#ifndef TAINT_ANALYSIS_INSTR_TAINTGRIND_H
#define TAINT_ANALYSIS_INSTR_TAINTGRIND_H

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstVisitor.h"

using namespace llvm;

namespace TaintAnalysis {
    struct InstrTaintgrindVisitor : public InstVisitor<InstrTaintgrindVisitor> {
    private:
        std::vector<Instruction*> taintSources;

    public:
        InstrTaintgrindVisitor() {}

        void visitAllocaInst(AllocaInst &I) {
            taintSources.push_back(&I);
        }
        
        void visitInstruction(Instruction &I) {}  // Ignore unhandled instructions

        /// @return true if the taint for this function changed
        bool instrumentFunction(Function& f) {
            taintSources.clear();
            visit(f);

            for (auto it = taintSources.begin(); it != taintSources.end(); ++it) {
                // Ok, let's taint that value!
                Instruction* taintSource = *it;

                IRBuilder<> builder(getGlobalContext());
                
                // TODO 1. move all instructions after the source to a new BasicBlock
                BasicBlock* startBlock = taintSource->getParent();
                BasicBlock* endBlock = BasicBlock::Create(getGlobalContext(), "instrEnd", startBlock->getParent());
                bool move = false;
                std::vector<Instruction*> toMove;
                for (auto it2 = startBlock->begin(); it2 != startBlock->end(); ++it2) {
                    if (move) {
                        toMove.push_back(&(*it2));
                    } else {
                        move = (&(*it2) == taintSource);
                    }
                }

                for (auto it3 = toMove.begin(); it3 != toMove.end(); ++it3) {
                    (*it3)->removeFromParent();
                    endBlock->getInstList().push_back(*it3);
                }

                endBlock->getParent()->print(errs());
                errs() << "\n\n";
                                
                // TODO 2. Store the value in a newly allocated memory cell
                builder.SetInsertPoint(endBlock);

                Instruction* alloca = new AllocaInst(taintSource->getType(), "tmp", startBlock);
                alloca->print(errs());
                errs() << "\n";

                Instruction* storeV = new StoreInst(taintSource, alloca, startBlock);
                storeV->print(errs());

                // TODO 3. insert the taintgrind instrumentation

                // TODO 4. load the value from memory again and replace all usages of the taint source with the loaded value

                break;
            }
            
            return !taintSources.empty();
        }

        /// @return true if the module was modified
        bool instrumentModule(Module& M) {
            bool modified = false;

            // iterate over the functions in the module and instrument them
            for (Module::iterator mi = M.begin(), me = M.end(); mi != me; ++mi) {
                Function& f = *mi;
                bool tc = instrumentFunction(f);
                modified = modified || tc;
            }

            return modified;
        }
    };
}

#endif
