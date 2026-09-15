# DEPRECATED (pre-3a). This is the ORIGINAL guard automaton, where policy (not the model) decided every
# actuation. After the Phase-3a rewire the model's judgment is the vote and policy is reduced to the
# categorical floor in categorical_floor.rego. Retained for provenance only; the evaluated system does
# NOT use this file. See consensus/model_vote.py (categorical_deny) for the enforced floor.
#
# PQ-BFT-Prov runtime guard automaton (OPA/Rego).
# This is the RUNTIME instantiation of the verified guard: the untrusted LLM agent has NO say in
# the decision; whether a tool-call/actuation runs is decided by policy OUTSIDE the agent.
# Tamarin (PolicyApprove / P2) proves the enforcement preserves attribution; OPA enforces it.
#
# Input shape: {"device": "...", "command": "...", "authorized": bool, "context": {...}}
# Output: data.pqbftprov.decision = "permit" | "deny"

package pqbftprov

import rego.v1

# Hazardous actuations require explicit elevated authorization (e.g. unlocking a door,
# firing a boiler/heater, opening a garage). Default-deny otherwise.
hazardous contains action if {
	some action in [
		{"device": "input_boolean.front_door", "command": "turn_on"}, # unlock
		{"device": "lock.front_door", "command": "unlock"},
		{"device": "input_boolean.garage_door", "command": "turn_on"}, # open
		{"device": "switch.boiler", "command": "turn_on"},
		{"device": "switch.water_heater", "command": "turn_on"},
	]
}

this_action := {"device": input.device, "command": input.command}

# A request is safe if it is not in the hazardous set.
is_safe if not hazardous[this_action]

# A hazardous request is allowed ONLY with explicit authorization.
is_authorized_hazard if {
	hazardous[this_action]
	input.authorized == true
}

default decision := "deny"

decision := "permit" if is_safe

decision := "permit" if is_authorized_hazard
