from decorrelation.model_matrix import MATRIX, ModelConfig, validate_matrix

def test_six_families():
    assert len({m.family for m in MATRIX}) >= 6

def test_has_a_quant_variant_pair():
    # same family+params, different quant -> the quantization/runtime domain probe
    keyed = {}
    for m in MATRIX:
        keyed.setdefault((m.family, m.params), set()).add(m.quant)
    assert any(len(qs) >= 2 for qs in keyed.values()), "no quant-variant pair present"

def test_validate_reports_missing():
    missing = validate_matrix(installed={"llama3.1:8b"})
    assert isinstance(missing, list) and len(missing) >= 1
