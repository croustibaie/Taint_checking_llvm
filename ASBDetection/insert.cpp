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
        Function* hook;

        bishe_insert() : ModulePass(ID) {}

        virtual bool runOnModule(Module &M) {
            // void print(int64)
            LLVMContext& ctx = M.getContext();
            Constant* hookFunc = M.getOrInsertFunction("print",
                FunctionType::getVoidTy(ctx), Type::getInt64Ty(ctx), nullptr);
            hook = cast<Function>(hookFunc);
            
            // iterate over the functions in the module
            for (Module::iterator mi = M.begin(), me = M.end(); mi != me; ++mi) {
                // iterate over the basic blocks in the function
                for (Function::iterator fi = mi->begin(), fe = mi->end(); fi != fe; ++fi) {
                    /*fi->dump();
                    if (fi->hasName())
                    errs() << fi->getName();*/
                    runOnBasicBlock(fi);
                }
            }

            return false;
        }
        
        virtual bool runOnBasicBlock(Function::iterator &fi) {
            // iterate over the items in the basic block
            for (BasicBlock::iterator bi = fi->begin(), be = fi->end(); bi != be; ++bi) {
                // find all cast instructions
                if (CastInst* castInst = dyn_cast<CastInst>(bi)) {
                    // only if this is a cast from ptr to int
                    if (castInst->getSrcTy()->isPointerTy() && castInst->getDestTy()->isIntegerTy()) {
                        /*Value *operand = castInst->getOperand(0);
                        operand->printAsOperand(errs());
                        errs() << "\n";*/
                        
                        errs() << "Found cast instruction of type: ";
                        castInst->getType()->print(errs());
                        errs() << "\n";
                        
                        // create and insert the print instruction that prints the value of the pointer
                        ArrayRef<Value*> args = ArrayRef<Value*>(castInst);
                        Instruction *newInst = CallInst::Create(hook, args, "");
                        fi->getInstList().insertAfter((Instruction*) castInst, newInst);
                    }
                }
            }
            return true;
        }
    };
}

char bishe_insert::ID = 0;
static RegisterPass<bishe_insert> X("bishe_insert", "test function exist", false, false);
