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

#include "taint.h"
//#include "dump.h"

using namespace llvm;

namespace TaintAnalysis {
    struct TaintVisitor : public InstVisitor<TaintVisitor, Taint> {
    private:
        std::vector<Taint> retTaints;

    public:
        typedef std::map<Function*, Taint> FunTaints;
        static FunTaints functionTaints;
        
        TaintVisitor() {}

        Taint getReturnTaint() {
            if (retTaints.empty()) {
                return Taint(TAINT_NONE);
            } else {
                return Taint(retTaints);
            }
        }

        Taint treatValue(Value* val) {
            if (isa<Constant>(val)) {
                return Taint(TAINT_NONE);
            } else if (isa<Instruction>(val)) {
                return visit(dyn_cast<Instruction>(val));
            } else if (isa<Argument>(val)) {
                return Taint({val});
            } else if (!isa<MetadataAsValue>(val)) {
                assert(false); // NOT IMPLEMENTED
            }
        }
        
        Taint treatInstruction(Instruction &inst) {
            std::vector<Taint> opTaints;
            
            for (int i = 0; i < inst.getNumOperands(); ++i) {
                Value *op = inst.getOperand(i);
                opTaints.push_back(treatValue(op));
            }

            return Taint(opTaints);
        }

        Taint visitReturnInst(ReturnInst &I)            {
            retTaints.push_back(treatValue(I.getReturnValue()));
            return Taint(TAINT_NONE);
        }
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
            return Taint(TAINT_DEFINITELY);
        }
        Taint visitLoadInst(LoadInst     &I)            {
            return Taint(TAINT_MAYBE);
        }
        Taint visitStoreInst(StoreInst   &I)            {
            return Taint(TAINT_NONE);
        }
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
        Taint visitDbgDeclareInst(DbgDeclareInst &I)    { return Taint(TAINT_NONE);}
        Taint visitDbgValueInst(DbgValueInst &I)        { return Taint(TAINT_NONE);}
        Taint visitDbgInfoIntrinsic(DbgInfoIntrinsic &I) { return Taint(TAINT_NONE); }
        Taint visitMemSetInst(MemSetInst &I)            { return treatInstruction(I); }
        Taint visitMemCpyInst(MemCpyInst &I)            { return treatInstruction(I); }
        Taint visitMemMoveInst(MemMoveInst &I)          { return treatInstruction(I); }
        Taint visitMemTransferInst(MemTransferInst &I)  { return treatInstruction(I); }
        Taint visitMemIntrinsic(MemIntrinsic &I)        { return treatInstruction(I); }
        Taint visitVAStartInst(VAStartInst &I)          { return treatInstruction(I); }
        Taint visitVAEndInst(VAEndInst &I)              { return treatInstruction(I); }
        Taint visitVACopyInst(VACopyInst &I)            { return treatInstruction(I); }
        Taint visitIntrinsicInst(IntrinsicInst &I)      { return treatInstruction(I); }

        Taint visitCallInst(CallInst &I) {
            Function* f = I.getCalledFunction();
            if (f->getReturnType() == FunctionType::getVoidTy(I.getContext())) {
                return Taint(TAINT_NONE);
            } else {
                FunTaints::iterator it = functionTaints.find(f);
                if (it != functionTaints.end()) {
                    return it->second;
                } else {
                    return Taint(TAINT_MAYBE);
                }
            }
        }
        Taint visitInvokeInst(InvokeInst &I) {
            assert(false && "not implemented");
            return treatInstruction(I);
        }
        
        Taint visitInstruction(Instruction &I) { return treatInstruction(I); }  // Ignore unhandled instructions

        /// @return true if the taint for this function changed
        static bool globalVisitFunction(Function& f) {
            TaintVisitor v;
            v.visit(f);
            Taint retTaint = v.getReturnTaint();

            bool taintChanged = true;
            auto it = functionTaints.find(&f);
            if (it != functionTaints.end()) {
                taintChanged = retTaint != it->second;
            }
            
            TaintVisitor::functionTaints[&f] = retTaint;

            return taintChanged;
        }
    };


    struct bishe_insert : public ModulePass {
        static char ID;  
        Function* hook;

        bishe_insert() : ModulePass(ID) {}

        virtual bool runOnModule(Module &M) {
            bool taintChanged = true;

            while (taintChanged) {
                taintChanged = false;
                
                // iterate over the functions in the module
                for (Module::iterator mi = M.begin(), me = M.end(); mi != me; ++mi) {
                    Function& f = *mi;
                    bool tc = TaintVisitor::globalVisitFunction(f);
                    taintChanged |= tc;
                }

                // errs() << "--------------------------------------------------------------------------------\n\n";
            }

            // dump the final taint results
            //DumpTaintVisitor dumper();
            
            // the module was not modified -> return false
            return false;
        }
    };

    TaintVisitor::FunTaints TaintVisitor::functionTaints;

    char bishe_insert::ID = 0;
    static RegisterPass<bishe_insert> X("bishe_insert", "test function exist", false, false);
}
