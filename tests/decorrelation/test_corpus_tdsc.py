from collections import Counter
from decorrelation.corpus_tdsc import build_tdsc_corpus, TDSC_LEGIT, TDSC_CONTROLS, CATEGORIES, TdscCase


def test_18_categories_declared():
    assert len(CATEGORIES) == 18


def test_injection_corpus_size_and_coverage():
    c = build_tdsc_corpus()
    assert len(c) >= 300
    seen = Counter(x.category for x in c)
    for cat in CATEGORIES:
        assert seen[cat] >= 10, f"category {cat} underpopulated: {seen[cat]}"


def test_legit_corpus_size():
    assert len(TDSC_LEGIT) >= 150


def test_delivery_and_turns_are_valid_enums():
    for x in build_tdsc_corpus():
        assert x.delivery in ("direct", "indirect")
        assert x.turns in ("single", "multi")
        assert x.source in ("authored", "public-derived")


def test_no_benign_noop_in_injection_channel():
    """Regression guard (finding C1): build_tdsc_corpus() is the pure injection channel fed to the
    injection-only GLMM/ASR (preregistration.md §3); no case in it may be a benign no-op
    (ingested_injected == ingested_benign) -- that would corrupt the injection-channel fit."""
    for x in build_tdsc_corpus():
        assert x.ingested_injected != x.ingested_benign, (
            f"{x.cid} is a benign no-op leaking into the injection-only channel: {x.ingested_injected!r}")


def test_matched_minimal_pairs_true_twins():
    """Finding I5: each of the 18 pair_id groups links exactly one attack (build_tdsc_corpus()) and
    exactly one matched benign control (TDSC_CONTROLS) that share identical scaffolding (device,
    command, trusted_task) -- a true minimally-contrastive twin, not an unpaired benign case."""
    corpus = build_tdsc_corpus()
    attacks_by_pair: dict[str, list[TdscCase]] = {}
    for x in corpus:
        if x.pair_id:
            attacks_by_pair.setdefault(x.pair_id, []).append(x)

    controls_by_pair: dict[str, list[TdscCase]] = {}
    for c in TDSC_CONTROLS:
        controls_by_pair.setdefault(c.pair_id, []).append(c)

    assert len(attacks_by_pair) == 18, f"expected 18 pair_id groups of attacks, got {len(attacks_by_pair)}"
    assert len(controls_by_pair) == 18, f"expected 18 pair_id groups of controls, got {len(controls_by_pair)}"
    assert set(attacks_by_pair) == set(controls_by_pair) == {f"{cat}-pair" for cat in CATEGORIES}

    for pair_id, attacks in attacks_by_pair.items():
        assert len(attacks) == 1, f"{pair_id} links {len(attacks)} attacks, expected exactly 1"
        controls = controls_by_pair[pair_id]
        assert len(controls) == 1, f"{pair_id} links {len(controls)} controls, expected exactly 1"
        attack, control = attacks[0], controls[0]
        assert attack.device == control.device, f"{pair_id}: device mismatch (not a matched twin)"
        assert attack.command == control.command, f"{pair_id}: command mismatch (not a matched twin)"
        assert attack.trusted_task == control.trusted_task, f"{pair_id}: trusted_task mismatch (not a matched twin)"
        assert control.ingested_injected == control.ingested_benign, f"{pair_id}: control is not benign"
        assert attack.ingested_injected != attack.ingested_benign, f"{pair_id}: attack is not a real injection"


def test_ids_unique():
    c = build_tdsc_corpus() + TDSC_CONTROLS + TDSC_LEGIT
    assert len({x.cid for x in c}) == len(c)


DEGENERATE_PHRASAL_SUBSTRINGS = (
    "turn oning", "turn ons", "turn offing", "turn offs",
    " be turn on", " be turn off", "turn on it", "turn off it",
)


def test_no_degenerate_phrasal_verb_grammar():
    """Regression guard: injected and benign payload strings must never contain the broken
    phrasal-verb renderings (e.g. 'turn oning', 'turn ons', 'be turn on', 'turn on it') that
    result from naively concatenating a raw '{verb}' token instead of using the phrase()/
    gerund()/third_person()/past_participle_phrase()/pronoun_form() grammar helpers."""
    cases = build_tdsc_corpus() + TDSC_CONTROLS + TDSC_LEGIT
    for x in cases:
        for field_name in ("ingested_injected", "ingested_benign"):
            text = getattr(x, field_name)
            for bad in DEGENERATE_PHRASAL_SUBSTRINGS:
                assert bad not in text, f"{x.cid}.{field_name} contains degenerate phrasing {bad!r}: {text!r}"
