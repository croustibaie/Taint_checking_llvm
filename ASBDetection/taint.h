#ifndef TAINT_ANALYSIS_TAINT_H
#define TAINT_ANALYSIS_TAINT_H

#include <assert.h>
#include <set>

using namespace llvm;

namespace TaintAnalysis {
    enum TaintKind {
        TAINT_NONE,
        TAINT_MAYBE,
        TAINT_DEFINITELY
    };

    class Taint {
      public:
        typedef std::map<const Value*, Taint> Tenv;

        Taint() : _kind(TAINT_NONE) {}
        Taint(const TaintKind tk) : _kind(tk) {}
        Taint(std::initializer_list<Value*> paramsList) : _kind(TAINT_MAYBE), params(paramsList) {
            assert(params.size() > 0 && "Use constructor 'Taint(const TaintKind)' instead");
        }
        Taint(std::set<Value*> paramsList) : _kind(TAINT_MAYBE), params(paramsList) {
            assert(params.size() > 0 && "Use constructor 'Taint(const TaintKind)' instead");
        }
        Taint(std::initializer_list<Taint> opTaints) : Taint(std::vector<Taint>(opTaints)) {}
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
                assert((_kind != TAINT_NONE || params.empty()) && "None-Taint must not have parameters");
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

        Taint apply(Tenv& env) {
            if (params.empty()) {
                return *this;
            } else {
                std::set<Value*> unassignedParams;
                std::vector<Taint> arguments;
                
                for (Value* param : params) {
                    Tenv::iterator it = env.find(param);
                    if (it == env.end()) {
                        unassignedParams.insert(param);
                    } else {
                        // some speedup here
                        if (it->second.kind() == TAINT_DEFINITELY) {
                            return Taint(TAINT_DEFINITELY);
                        }
                        
                        arguments.push_back(it->second);
                    }
                }

                if (!unassignedParams.empty()) {
                    arguments.push_back(Taint(unassignedParams));
                }
                
                return Taint(arguments);
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
