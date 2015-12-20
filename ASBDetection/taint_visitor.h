#ifndef TAINT_ANALYSIS_TAINT_VISITOR_H
#define TAINT_ANALYSIS_TAINT_VISITOR_H

#include "llvm/IR/InstVisitor.h"

#include "taint.h"

using namespace llvm;

namespace TaintAnalysis {
    struct TaintVisitor : public InstVisitor<TaintVisitor, Taint> {
    private:
        typedef std::map<Instruction*, Taint> InstrTaints;
        typedef std::map<Function*, Taint> FunTaints;
        FunTaints functionTaints;
        InstrTaints taints;
        std::vector<Taint> retTaints;

    public:
        TaintVisitor() {}
        TaintVisitor(FunTaints functionTaints) : functionTaints(functionTaints) {}

        Taint getReturnTaint() {
            if (retTaints.empty()) {
                return Taint(TAINT_NONE);
            } else {
                return Taint(retTaints);
            }
        }

        Taint getTaint(Instruction* instr) {
            assert(taints.find(instr) != taints.end() && "instruction doesn't have a taint");
            return taints.find(instr)->second;
        }

        Taint getTaint(Function* f) {
            assert(functionTaints.find(f) != functionTaints.end() && "function doesn't have a taint");
            return functionTaints.find(f)->second;
        }

        Taint makeConstTaint(Instruction& instr, TaintKind defaultTaint) {
            auto it = taints.find(&instr);
            if (it == taints.end()) {
                return taints[&instr] = Taint(defaultTaint);
            } else {
                return it->second;
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

        Taint treatInstruction(Instruction &instr) {
            auto it = taints.find(&instr);
            if (it != taints.end()) {
                return it->second;
            }
            
            std::vector<Taint> opTaints;
            
            for (int i = 0; i < instr.getNumOperands(); ++i) {
                Value *op = instr.getOperand(i);
                opTaints.push_back(treatValue(op));
            }

            return taints[&instr] = Taint(opTaints);
        }

        Taint visitReturnInst(ReturnInst &I)            {
            retTaints.push_back(treatValue(I.getReturnValue()));
            return makeConstTaint(I, TAINT_NONE);
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
            return makeConstTaint(I, TAINT_DEFINITELY);
        }
        Taint visitLoadInst(LoadInst     &I)            {
            return makeConstTaint(I, TAINT_MAYBE);
        }
        Taint visitStoreInst(StoreInst   &I)            {
            return makeConstTaint(I, TAINT_NONE);
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
        Taint visitDbgDeclareInst(DbgDeclareInst &I)    { return makeConstTaint(I, TAINT_NONE);}
        Taint visitDbgValueInst(DbgValueInst &I)        { return makeConstTaint(I, TAINT_NONE);}
        Taint visitDbgInfoIntrinsic(DbgInfoIntrinsic &I) { return makeConstTaint(I, TAINT_NONE); }
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
            auto it = taints.find(&I);
            if (it != taints.end()) {
                return it->second;
            }
            
            Function* f = I.getCalledFunction();
            if (f->getReturnType() == FunctionType::getVoidTy(I.getContext())) {
                return makeConstTaint(I, TAINT_NONE);
            } else {
                FunTaints::iterator fit = functionTaints.find(f);
                if (fit != functionTaints.end()) {
                    return taints[&I] = fit->second;
                } else {
                    return makeConstTaint(I, TAINT_MAYBE);
                }
            }
        }
        Taint visitInvokeInst(InvokeInst &I) {
            assert(false && "not implemented");
            return treatInstruction(I);
        }
        
        Taint visitInstruction(Instruction &I) { return treatInstruction(I); }  // Ignore unhandled instructions

        /// @return true if the taint for this function changed
        bool taintFunction(Function& f) {
            retTaints.clear();
            
            visit(f);
            Taint retTaint = getReturnTaint();

            bool taintChanged = true;
            auto it = functionTaints.find(&f);
            if (it != functionTaints.end()) {
                taintChanged = retTaint != it->second;
            }

            if (taintChanged) {
                functionTaints[&f] = retTaint;
            }

            return taintChanged;
        }

        bool taintModule(Module& M) {
            bool taintChanged = false;
            taints.clear();

            // iterate over the functions in the module
            for (Module::iterator mi = M.begin(), me = M.end(); mi != me; ++mi) {
                Function& f = *mi;
                bool tc = taintFunction(f);
                taintChanged |= tc;
            }

            return taintChanged;
        }
    };
}

#endif
