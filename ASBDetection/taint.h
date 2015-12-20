#ifndef TAINT_H
#define TAINT_H

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

namespace TaintAnalysis {
    enum TaintKind {
        TAINT_NONE,
        TAINT_MAYBE,
        TAINT_DEFINITELY
    };

    class Taint {
      public:
        typedef std::map<Value*, TaintKind> Tenv;

        Taint() : _kind(TAINT_NONE) {}
        Taint(const TaintKind tk) : _kind(tk) {}
        Taint(std::initializer_list<Value*> paramsList) : _kind(TAINT_MAYBE), params(paramsList) {
            assert(params.size() > 0 && "Use constructor 'Taint(const TaintKind)' instead");
        }
        Taint(std::vector<Taint> opTaints);

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

        bool operator==(Taint& other) {
            return (kind() == other.kind()) && (params == other.params);
        }

        bool operator!=(Taint& other) {
            return !(*this == other);
        }

      private:
        TaintKind _kind;
        std::set<Value*> params;
    };
}

#endif
