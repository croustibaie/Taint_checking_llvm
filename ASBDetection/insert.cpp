#include <assert.h>
#include <set>

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
    enum TaintKind {
        TAINT_NONE,
        TAINT_MAYBE,
        TAINT_DEFINITELY
    };

    class Taint {
    public:
        typedef std::map<Value*, TaintKind> Tenv;
        
        Taint(const TaintKind tk) : _kind(tk) {}
        Taint(std::initializer_list<Value*> paramsList) : _kind(TAINT_MAYBE), params(paramsList) {
            assert(params.size() > 0 && "Use constructor 'Taint(const TaintKind)' instead");
        }
        Taint(std::vector<Taint> opTaints) : _kind(TAINT_NONE) {
            assert(opTaints.size() > 0 && "Use constructor 'Taint(const TaintKind)' instead");

            for (Taint t : opTaints) {
                _kind = mergeTaintKinds(_kind, t.kind());
                if (_kind == TAINT_DEFINITELY) {
                    break;
                }
            }

            // if this is not definitely tainted anyway we can merge all params together
            if (_kind != TAINT_DEFINITELY) {
                for (Taint t : opTaints) {
                    params.insert(t.params.begin(), t.params.end());
                }
            }
        }

        static TaintKind mergeTaintKinds(TaintKind t1, TaintKind t2) {
            switch (t1) {
            case TAINT_NONE:
                return t2;
            case TAINT_MAYBE:
                return (t2 == TAINT_DEFINITELY) ? t2 : TAINT_MAYBE;
            case TAINT_DEFINITELY:
                return TAINT_DEFINITELY;
            default:
                assert(false);
            }
        }

        TaintKind evalKind(Tenv& env) {
            if (params.empty()) {
                return _kind;
            } else {
                TaintKind res = TAINT_NONE;
                for (Value* param : params) {
                    Tenv::iterator it = env.find(param);
                    res = mergeTaintKinds(res, it == env.end() ? TAINT_MAYBE : it->second);
                    if (res == TAINT_DEFINITELY) {
                        break;
                    }
                }
                return res;
            }
        }

        void dump(raw_ostream& stream) {
            switch (kind()) {
            case TAINT_NONE:
                stream << "TAINT_NONE";
                break;
            case TAINT_MAYBE:
                stream << "TAINT_MAYBE";
                break;
            case TAINT_DEFINITELY:
                stream << "TAINT_DEFINITELY";
                break;
            default:
                assert(false);
            }

            if (!params.empty()) {
                stream << "(";

                std::string sep = "";
                for (Value* param : params) {
                    stream << sep << param->getName();
                    sep = ", ";
                }
                
                stream << ")";
            }
        }

        TaintKind kind() {
            return _kind;
        }

    private:
        TaintKind _kind;
        std::set<Value*> params;
    };

    struct CountAllocaVisitor : public InstVisitor<CountAllocaVisitor, Taint> {
        int verbosity;
        
        CountAllocaVisitor() : verbosity(1) {}

        Taint treatInstruction(Instruction &inst) {
            if (verbosity > 0) inst.print(errs());
            if (verbosity > 1) errs() << "  :\n";

            std::vector<Taint> opTaints;
            
            for (int i = 0; i < inst.getNumOperands(); ++i) {
                Value *op = inst.getOperand(i);
                if (verbosity > 1) errs() << "    ";
                if (verbosity > 1) op->printAsOperand(errs());

                if (isa<Constant>(op)) {
                    if (verbosity > 1) errs() << " :: CONSTANT -> TAINT_NONE";
                    opTaints.push_back(Taint(TAINT_NONE));
                } else if (isa<Instruction>(op)) {
                    if (verbosity > 1) errs() << " :: INSTRUCTION -> ";

                    int oldVerbosity = verbosity;
                    verbosity = 0;
                    Taint opTaint = visit(dyn_cast<Instruction>(op));
                    verbosity = oldVerbosity;

                    if (verbosity > 1) opTaint.dump(errs());
                    
                    opTaints.push_back(opTaint);
                } else if (isa<Argument>(op)) {
                    if (verbosity > 1) errs() << " :: ARGUMENT -> TAINT_MAYBE";

                    opTaints.push_back(Taint({op}));
                } else if (!isa<MetadataAsValue>(op)) {
                    assert(false); // NOT IMPLEMENTED
                }

                if (verbosity > 1) errs() << "\n";
            }

            Taint taint = Taint(opTaints);
            
            if (verbosity > 0) errs() << "    -> ";
            if (verbosity > 0) taint.dump(errs());
            if (verbosity > 0) errs() << "\n";
            
            if (verbosity > 1) errs() << "\n";

//            if (inst.getDebugLoc())
//                errs() << inst.getDebugLoc().getLine();

            return taint;
        }

        Taint printWithTaint(Instruction& instr, Taint t) {
            if (verbosity > 0) {
                instr.print(errs());
                errs() << "    -> ";
                t.dump(errs());
                errs() << "\n";
            }
            if (verbosity > 1) {
                errs() << "\n";
            }
            return t;
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
            return printWithTaint(I, Taint(TAINT_DEFINITELY));
        }
        Taint visitLoadInst(LoadInst     &I)            {
            return printWithTaint(I, Taint(TAINT_MAYBE));
        }
        Taint visitStoreInst(StoreInst   &I)            {
            return printWithTaint(I, Taint(TAINT_NONE));
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
            /*LLVMContext& ctx = M.getContext();
            Constant* hookFunc = M.getOrInsertFunction("print",
                FunctionType::getVoidTy(ctx), Type::getInt64Ty(ctx), nullptr);
                hook = cast<Function>(hookFunc);*/
            
            // iterate over the functions in the module
            for (Module::iterator mi = M.begin(), me = M.end(); mi != me; ++mi) {
                errs() << mi->getName() << "(";

                std::string sep("");
                const Function::ArgumentListType& argList = mi->getArgumentList();
                for (Function::ArgumentListType::const_iterator it = argList.begin(); it != argList.end(); ++it) {
                    errs() << sep;
                    it->print(errs());
                    sep = ", ";
                }
                
                errs() << "):\n";
                
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
            errs() << fi->getName() << ":\n";
            
            CountAllocaVisitor v;
            v.visit(*fi);

            errs() << "\n";
        
            // Iterate over the items in the basic block
            /*for (BasicBlock::iterator bi = fi->begin(), be = fi->end(); bi != be; ++bi) {
                // find all cast instructions
                if (CastInst* castInst = dyn_cast<CastInst>(bi)) {
                    // only if this is a cast from ptr to int
                    if (castInst->getSrcTy()->isPointerTy() && castInst->getDestTy()->isIntegerTy()) {
                        //Value *operand = castInst->getOperand(0);
                        //operand->printAsOperand(errs());
                        //errs() << "\n";
                        
                        errs() << "Found cast instruction of type: ";
                        castInst->getType()->print(errs());
                        errs() << "\n";
                        
                        // create and insert the print instruction that prints the value of the pointer
                        ArrayRef<Value*> args = ArrayRef<Value*>(castInst);
                        Instruction *newInst = CallInst::Create(hook, args, "");
                        fi->getInstList().insertAfter((Instruction*) castInst, newInst);
                    }
                }
            }*/
            return true;
        }
    };
}

char bishe_insert::ID = 0;
static RegisterPass<bishe_insert> X("bishe_insert", "test function exist", false, false);
