TaintAnalysis::Taint(std::vector<Taint> opTaints) : _kind(TAINT_NONE) {
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
