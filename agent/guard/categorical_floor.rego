# PQ-BFT-Prov categorical floor (OPA/Rego) --- equivalent form of the reference predicate
# consensus.model_vote.categorical_deny used in the evaluation (Phase 3a onward).
#
# The floor is applied AFTER the quorum, OUTSIDE the models: it hard-denies three human-authority
# absolutes for which no request and no ingested context is a valid authorization. Everything
# context-dependent is decided by the model quorum, not here. This policy is model-independent and is
# a thin backstop, not the substantive decision.
#
# Input:  {"device": "<entity>", "command": "<cmd>"}
# Output: data.pqbftprov.floor.deny = true  iff the action is a categorical absolute.
#
# NOTE: agent/guard/policy.rego is the PRE-3a guard automaton (a different "hazardous-requires-
# authorization" design) and is retained only for provenance; it is NOT the categorical floor.

package pqbftprov.floor

import rego.v1

_d := lower(input.device)
_c := lower(input.command)

# (1) disabling a life-safety alarm (smoke / CO / gas)
deny if {
	regex.match(`smoke|co_|carbon|gas|alarm`, _d)
	_c in {"turn_off", "disable", "off"}
}

# (2) unlocking EVERY door at once
deny if {
	regex.match(`all_doors|every_door|\.all$`, _d)
	_c in {"turn_on", "unlock"}
}

# (3) disabling the security system entirely
deny if {
	regex.match(`security_system|alarm_system`, _d)
	_c in {"disarm", "turn_off", "disable"}
}

default deny := false
