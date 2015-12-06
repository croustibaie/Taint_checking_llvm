#include <assert.h>

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
#include "llvm/IR/InstVisitor.h"

using namespace llvm;

namespace {
    enum Taint {
        TAINT_NONE,
        TAINT_MAYBE,
        TAINT_DEFINITELY
    };
    
    struct CountAllocaVisitor : public InstVisitor<CountAllocaVisitor, Taint> {
        bool verbose;
        
        CountAllocaVisitor() : verbose(true) {}

        Taint mergeTaints(Taint t1, Taint t2) {
            switch (t1) {
            case TAINT_NONE:
                return t2;
            case TAINT_MAYBE:
                if (t2 != TAINT_DEFINITELY) {
                    return TAINT_MAYBE;
                } else {
                    return t2;
                }
            case TAINT_DEFINITELY:
                return TAINT_DEFINITELY;
            default:
                assert(false);
            }
        }

        Taint treatInstruction(Instruction &inst) {
            if (verbose) inst.print(errs());
            if (verbose) errs() << "  :\n";

            Taint taint = TAINT_NONE;
            
            for (int i = 0; i < inst.getNumOperands(); ++i) {
                Value *op = inst.getOperand(i);
                if (verbose) errs() << "    ";
                if (verbose) op->printAsOperand(errs());

                if (isa<Constant>(op)) {
                    if (verbose) errs() << " :: CONSTANT -> TAINT_NONE";
                } else if (isa<Instruction>(op)) {
                    if (verbose) errs() << " :: INSTRUCTION -> ";
                    bool oldVerbose = verbose;
                    verbose = false;
                    Taint opTaint = visit(dyn_cast<Instruction>(op));
                    verbose = oldVerbose;

                    if (verbose) printTaint(opTaint);
                    
                    taint = mergeTaints(taint, opTaint);
                } else if (isa<User>(op)) {
                    assert(false); // NOT IMPLEMENTED
                } else {
                    // this is probably a function param then
                    if (verbose) errs() << " :: VALUE -> TAINT_MAYBE";
                    
                    taint = mergeTaints(taint, TAINT_MAYBE);
                }
                
                if (verbose) errs() << "\n";
            }
            
            if (verbose) errs() << "    --> ";
            if (verbose) printTaint(taint);
            if (verbose) errs() << "\n";
            
            if (verbose) errs() << "\n";
            return taint;
        }

        bool printTaint(Taint t) {
            switch (t) {
            case TAINT_NONE:
                errs() << "TAINT_NONE";
                break;
            case TAINT_MAYBE:
                errs() << "TAINT_MAYBE";
                break;
            case TAINT_DEFINITELY:
                errs() << "TAINT_DEFINITELY";
                break;
            }
        }
        
        Taint visitReturnInst(ReturnInst &I)            { return treatInstruction(I);}
        Taint visitBranchInst(BranchInst &I)            { return treatInstruction(I);}
        Taint visitSwitchInst(SwitchInst &I)            { return treatInstruction(I);}
        Taint visitIndirectBrInst(IndirectBrInst &I)    { return treatInstruction(I);}
        Taint visitResumeInst(ResumeInst &I)            { return treatInstruction(I);}
        Taint visitUnreachableInst(UnreachableInst &I)  { return treatInstruction(I);}
        Taint visitCleanupReturnInst(CleanupReturnInst &I) { return treatInstruction(I);}
        Taint visitCleanupEndPadInst(CleanupEndPadInst &I) { return treatInstruction(I); }
        Taint visitCatchReturnInst(CatchReturnInst &I)  { return treatInstruction(I); }
        Taint visitCatchPadInst(CatchPadInst &I)    { return treatInstruction(I);}
        Taint visitCatchEndPadInst(CatchEndPadInst &I) { return treatInstruction(I); }
        Taint visitTerminatePadInst(TerminatePadInst &I) { return treatInstruction(I);}
        Taint visitICmpInst(ICmpInst &I)                { return treatInstruction(I);}
        Taint visitFCmpInst(FCmpInst &I)                { return treatInstruction(I);}
        Taint visitAllocaInst(AllocaInst &I)            {
            if (verbose) I.print(errs());
            if (verbose) errs() << "  -> TAINT_DEFINITELY\n\n";
            return TAINT_DEFINITELY;
        }
        Taint visitLoadInst(LoadInst     &I)            {
            if (verbose) I.print(errs());
            if (verbose) errs() << "  -> TAINT_MAYBE\n\n";
            return TAINT_MAYBE;
        }
        Taint visitStoreInst(StoreInst   &I)            { return treatInstruction(I);}
        Taint visitAtomicCmpXchgInst(AtomicCmpXchgInst &I) { return treatInstruction(I);}
        Taint visitAtomicRMWInst(AtomicRMWInst &I)      { return treatInstruction(I);}
        Taint visitFenceInst(FenceInst   &I)            { return treatInstruction(I);}
        Taint visitGetElementPtrInst(GetElementPtrInst &I){ return treatInstruction(I);}
        Taint visitPHINode(PHINode       &I)            { return treatInstruction(I);}
        Taint visitTruncInst(TruncInst &I)              { return treatInstruction(I);}
        Taint visitZExtInst(ZExtInst &I)                { return treatInstruction(I);}
        Taint visitSExtInst(SExtInst &I)                { return treatInstruction(I);}
        Taint visitFPTruncInst(FPTruncInst &I)          { return treatInstruction(I);}
        Taint visitFPExtInst(FPExtInst &I)              { return treatInstruction(I);}
        Taint visitFPToUIInst(FPToUIInst &I)            { return treatInstruction(I);}
        Taint visitFPToSIInst(FPToSIInst &I)            { return treatInstruction(I);}
        Taint visitUIToFPInst(UIToFPInst &I)            { return treatInstruction(I);}
        Taint visitSIToFPInst(SIToFPInst &I)            { return treatInstruction(I);}
        Taint visitPtrToIntInst(PtrToIntInst &I)        { return treatInstruction(I);}
        Taint visitIntToPtrInst(IntToPtrInst &I)        { return treatInstruction(I);}
        Taint visitBitCastInst(BitCastInst &I)          { return treatInstruction(I);}
        Taint visitAddrSpaceCastInst(AddrSpaceCastInst &I) { return treatInstruction(I);}
        Taint visitSelectInst(SelectInst &I)            { return treatInstruction(I);}
        Taint visitVAArgInst(VAArgInst   &I)            { return treatInstruction(I);}
        Taint visitExtractElementInst(ExtractElementInst &I) { return treatInstruction(I);}
        Taint visitInsertElementInst(InsertElementInst &I) { return treatInstruction(I);}
        Taint visitShuffleVectorInst(ShuffleVectorInst &I) { return treatInstruction(I);}
        Taint visitExtractValueInst(ExtractValueInst &I){ return treatInstruction(I);}
        Taint visitInsertValueInst(InsertValueInst &I)  { return treatInstruction(I); }
        Taint visitLandingPadInst(LandingPadInst &I)    { return treatInstruction(I); }
        Taint visitCleanupPadInst(CleanupPadInst &I) { return treatInstruction(I); }
        
        // Handle the special instrinsic instruction classes.
        Taint visitDbgDeclareInst(DbgDeclareInst &I)    { return treatInstruction(I);}
        Taint visitDbgValueInst(DbgValueInst &I)        { return treatInstruction(I);}
        Taint visitDbgInfoIntrinsic(DbgInfoIntrinsic &I) { return treatInstruction(I); }
        Taint visitMemSetInst(MemSetInst &I)            { return treatInstruction(I); }
        Taint visitMemCpyInst(MemCpyInst &I)            { return treatInstruction(I); }
        Taint visitMemMoveInst(MemMoveInst &I)          { return treatInstruction(I); }
        Taint visitMemTransferInst(MemTransferInst &I)  { return treatInstruction(I); }
        Taint visitMemIntrinsic(MemIntrinsic &I)        { return treatInstruction(I); }
        Taint visitVAStartInst(VAStartInst &I)          { return treatInstruction(I); }
        Taint visitVAEndInst(VAEndInst &I)              { return treatInstruction(I); }
        Taint visitVACopyInst(VACopyInst &I)            { return treatInstruction(I); }
        Taint visitIntrinsicInst(IntrinsicInst &I)      { return treatInstruction(I); }
        
        Taint visitInstruction(Instruction &I) { return treatInstruction(I); }  // Ignore unhandled instructions
    };


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
            CountAllocaVisitor v;
            v.visit(*fi);
        
            // Iterate over the items in the basic block
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
