#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Instruction.h"
#include "llvm/ADT/ArrayRef.h"

#include "llvm/IR/IRBuilder.h"



using namespace llvm;

namespace{
    struct bishe_insert : public ModulePass {
        static char ID;  
        Function *hook;

        bishe_insert() : ModulePass(ID) {}

        virtual bool runOnModule(Module &M) {
            Constant *hookFunc;
            hookFunc = M.getOrInsertFunction("print", FunctionType::getVoidTy(M.getContext()),Type::getInt64Ty(M.getContext()), (Type*)0);
              
            hook= cast<Function>(hookFunc);
            for(Module::iterator F = M.begin(), E = M.end(); F!= E; ++F) {
                for(Function::iterator BB = F->begin(), E = F->end(); BB != E; ++BB) {
                    /*BB->dump();
                    if (BB->hasName())
                    errs() << BB->getName();*/
                    bishe_insert::runOnBasicBlock(BB);
                }
            }

            return false;
        }
        
        virtual bool runOnBasicBlock(Function::iterator &BB) {
            for(BasicBlock::iterator BI = BB->begin(), BE = BB->end(); BI != BE; ++BI) {
                if(CastInst *CI = dyn_cast<CastInst>(BI)) {
                    if (CI->getSrcTy()->isPointerTy() && CI->getDestTy()->isIntegerTy()) {
                        /*Value *operand = CI->getOperand(0);
                        operand->printAsOperand(errs());
                        errs() << "\n";*/
                        CI->getType()->print(errs());
                        errs() << "\n";
                        ArrayRef<Value *> args = ArrayRef<Value *>(CI);
                        //ArrayRef<Value *> args= ArrayRef<Value *>();
                        Instruction *newInst = CallInst::Create(hook,args, "");
                        BB->getInstList().insertAfter((Instruction*)CI, newInst);                      
                    }
                }
            }
            return true;
        }
    };
}

char bishe_insert::ID = 0;
static RegisterPass<bishe_insert> X("bishe_insert", "test function exist", false, false);
