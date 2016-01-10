#ifndef TAINT_ANALYSIS_INSTR_TAINTGRIND_H
#define TAINT_ANALYSIS_INSTR_TAINTGRIND_H

#include "llvm/IR/InlineAsm.h"
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
                BasicBlock* startBlock = taintSource->getParent();

                IRBuilder<> builder(getGlobalContext());
                builder.SetInsertPoint(startBlock);

                // TODO 1. move all instructions after the source to a new BasicBlock
                BasicBlock* doBodyBlock = BasicBlock::Create(getGlobalContext(), "doBody", startBlock->getParent());
                
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

                logState(endBlock->getParent());

                // 2. Store the value in a newly allocated memory cell
                AllocaInst* taintCell = builder.CreateAlloca(taintSource->getType(), nullptr, "taintCell"); // TODO align 4?
                Instruction* storeTaintSrc = builder.CreateStore(taintSource, taintCell); // TODO align??

                logState(endBlock->getParent());
                
                // TODO 3. insert the taintgrind instrumentation
                // 3.a) create a taint label
                Value* taintLabel = builder.CreateGlobalStringPtr("taintBlue", "taintLabel"); // TODO align 1?
                
                // 3.b) allocate tmp vars
                Type* i64Ty = builder.getInt64Ty();
                Type* i64x6Ty = ArrayType::get(i64Ty, 6);
                AllocaInst* zzq_args = builder.CreateAlloca(i64x6Ty, nullptr, "_zzq_args"); // TODO align 16?
                AllocaInst* zzq_result = builder.CreateAlloca(i64Ty, nullptr, "_zzq_result"); // TODO align 8?
                AllocaInst* tmp = builder.CreateAlloca(i64Ty, nullptr, "tmp"); // TODO align 8?

                builder.CreateBr(doBodyBlock);
                builder.SetInsertPoint(doBodyBlock);
                
                // 3.c) spawn taintgrind instrumentation
                Value* arrayidx = builder.CreateConstInBoundsGEP2_64(zzq_args, 0, 0, "arrayidx");
                builder.CreateStore(ConstantInt::get(i64Ty, 12), arrayidx, true); // TODO align 16?

                Value* taintCellI64 = builder.CreatePtrToInt(taintCell, i64Ty);
                Value* arrayidx1 = builder.CreateConstInBoundsGEP2_64(zzq_args, 0, 1, "arrayidx1");
                builder.CreateStore(taintCellI64, arrayidx1, true); // TODO align 8?

                Value* arrayidx2 = builder.CreateConstInBoundsGEP2_64(zzq_args, 0, 2, "arrayidx2");
                builder.CreateStore(ConstantInt::get(i64Ty, 4), arrayidx2, true); // TODO align 16?

                Value* arrayidx3 = builder.CreateConstInBoundsGEP2_64(zzq_args, 0, 3, "arrayidx3");
                builder.CreateStore(builder.CreatePtrToInt(taintLabel, i64Ty), arrayidx3, true); // TODO align 8?

                Value* arrayidx4 = builder.CreateConstInBoundsGEP2_64(zzq_args, 0, 4, "arrayidx4");
                builder.CreateStore(ConstantInt::get(i64Ty, 0), arrayidx4, true); // TODO align 16?

                Value* arrayidx5 = builder.CreateConstInBoundsGEP2_64(zzq_args, 0, 5, "arrayidx5");
                builder.CreateStore(ConstantInt::get(i64Ty, 0), arrayidx5, true); // TODO align 8?

                Value* arrayidx6 = builder.CreateConstInBoundsGEP2_64(zzq_args, 0, 0, "arrayidx6");
                FunctionType* asmTy = FunctionType::get(i64Ty, {PointerType::getUnqual(i64Ty), i64Ty}, false);
                InlineAsm* tgAsm = InlineAsm::get(asmTy, "rolq $$3,  %rdi ; rolq $$13, %rdi\x0A\x09rolq $$61, %rdi ; rolq $$51, %rdi\x0A\x09xchgq %rbx,%rbx", "={dx},{ax},0,~{cc},~{memory},~{dirflag},~{fpsr},~{flags}", true);
                CallInst* callAsm = builder.CreateCall(tgAsm, {arrayidx6, ConstantInt::get(i64Ty, 0)});
                // TODO callAsm->addAttribute(0, Attribute::AttrKind::NoUnwind);

                builder.CreateStore(callAsm, zzq_result, true); // TODO align 8?
                Value* zzq_resultLoad = builder.CreateLoad(zzq_result, true); // TODO align 8?

                builder.CreateStore(zzq_resultLoad, tmp); // TODO align 8?
                builder.CreateLoad(tmp); // TODO align 8?
                
                logState(endBlock->getParent());
                
                // TODO 4. load the value from memory again and replace all usages of the taint source with the loaded value
                Value* taintedPtr = builder.CreateLoad(taintCell, "tainted_" + taintSource->getName());

                for (auto uit = taintSource->use_begin(); uit != taintSource->use_end(); ++uit) {
                    User* user = uit->getUser();
                    if (user != storeTaintSrc) {
                        // replace the taintSource with the taintedPtr
                        user->replaceUsesOfWith(taintSource, taintedPtr);
                    }
                }
                
                logState(endBlock->getParent());

                // 5. branch to the endBlock
                builder.CreateBr(endBlock);

                logState(endBlock->getParent());
            }
            
            return !taintSources.empty();
        }

        void logState(Function* f) {
            f->print(errs());
            errs() << "\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n";
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
