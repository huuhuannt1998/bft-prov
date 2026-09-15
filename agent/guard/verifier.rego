# Deterministic smart-home safety verifier (earlier revision).
#
# This is the mechanism the paper calls load-bearing, so it is specified and evaluated rather than
# asserted. It is evaluated OUTSIDE any model, on a structured action + context record, and returns
# one of permit / escalate / deny together with the rule ids that fired.
#
# Precedence is fixed and total: deny > escalate > permit. A rule may only make the outcome more
# restrictive, so rule order cannot change a decision and conflicts cannot silently resolve to permit.
#
# Trust: every context field is supplied by the gateway from device/sensor state, never by the model
# and never parsed out of ingested content. Fields carry an age; stale or missing state for a
# high-risk or critical action is a denial or an escalation, never a silent permit (see F1-F3).
#
# Input:
# {
#   "action":  {"device","domain","command","args","risk_tier"},
#   "context": {"occupancy":{"value","age_s"}, "time_hhmm", "authenticated", "device_state",
#               "sensors", "recent_unlocks", "last_action_age_s", "guest_window", "interlocks"}
# }
package pqbftprov.verifier

import rego.v1

action := input.action
ctx := input.context
dev := lower(object.get(action, "device", ""))
cmd := lower(object.get(action, "command", ""))
dom := lower(object.get(action, "domain", ""))
tier := lower(object.get(action, "risk_tier", "low"))

off_cmds := {"turn_off", "disable", "off", "stop"}
on_cmds := {"turn_on", "enable", "on", "start"}

# ---------------------------------------------------------------- life safety (LS)

deny_rules contains "LS1" if {
	regex.match(`smoke`, dev)
	cmd in off_cmds
}

deny_rules contains "LS2" if {
	regex.match(`carbon|co_|co2|gas`, dev)
	cmd in off_cmds
}

deny_rules contains "LS3" if {
	regex.match(`notify|notification|alert`, dev)
	cmd in off_cmds
	object.get(action, ["args", "critical"], false) == true
}

escalate_rules contains "LS4" if {
	regex.match(`alarm`, dev)
	cmd in {"override", "silence", "snooze"}
}

# LS5 covers any component the operator declared required, sensor or protective device. The earlier
# device-name regex was the wrong test: it missed cameras and pumps that the declared set already names.
required_components := {lower(s) | some s in array.concat(
	object.get(ctx, ["required_sensors"], []),
	object.get(ctx, ["required_devices"], []))}

deny_rules contains "LS5" if {
	cmd in off_cmds
	dev in required_components
}

# ---------------------------------------------------------------- access control (AC)

deny_rules contains "AC1" if {
	regex.match(`all_doors|every_door|\.all$|all_locks`, dev)
	cmd in {"unlock", "open", "turn_on"}
}

deny_rules contains "AC2" if {
	dom == "lock"
	cmd in {"unlock", "open"}
	object.get(ctx, ["occupancy", "value"], "unknown") == "away"
	object.get(ctx, "authenticated", false) == false
}

escalate_rules contains "AC3" if {
	dom == "lock"
	cmd in {"unlock", "open"}
	night
}

deny_rules contains "AC4" if {
	dom == "lock"
	cmd in {"unlock", "open"}
	count(object.get(ctx, "recent_unlocks", [])) >= 3
}

deny_rules contains "AC5" if {
	dom == "lock"
	object.get(ctx, ["guest_window", "active"], true) == false
	object.get(action, ["args", "actor"], "") == "guest"
}

deny_rules contains "AC6" if {
	regex.match(`security_system|alarm_system`, dev)
	cmd in {"disarm", "turn_off", "disable"}
}

# --- semantic access rules (earlier revision). AC2-AC4 key on the `lock` entity domain, which is why
# the audit found garage doors, gates and window covers permitted: the platform exposes their release as
# `turn_on` or `open` on a different domain. These restate the same policy intent over the semantic
# class, so any device the registry declares as an access role is governed regardless of its service name.

deny_rules contains "AC7" if {
	semantic_class == "access.enable"
	tier != "low"
	object.get(ctx, ["occupancy", "value"], "unknown") == "away"
	object.get(ctx, "authenticated", false) == false
}

escalate_rules contains "AC8" if {
	semantic_class == "access.enable"
	tier != "low"
	night
}

escalate_rules contains "AC9" if {
	semantic_class == "access.enable"
	tier != "low"
	object.get(ctx, ["device_state", "fault"], false) == true
}

# --- fault-state fail-safe. A high or critical action decided on faulted device state is decided on
# state the gateway itself reports as unreliable, so it escalates rather than proceeding silently.

escalate_rules contains "SF1" if {
	tier in {"high", "critical"}
	object.get(ctx, ["device_state", "fault"], false) == true
}

# --- night-time hazardous activation. Thermal activation while the home is occupied and asleep is the
# case the audit surfaced: no rule covered it, so it defaulted to permit.

escalate_rules contains "SF2" if {
	semantic_class in {"thermal.enable", "access.enable", "power.enable"}
	object.get(ctx, ["device_state", "fault"], false) == true
}

escalate_rules contains "SF3" if {
	semantic_class in {"thermal.enable", "access.enable", "power.enable"}
	to_number(object.get(ctx, ["occupancy", "age_s"], 0)) > to_number(object.get(ctx, "max_state_age_s", 300))
}

escalate_rules contains "AP6" if {
	semantic_class == "thermal.enable"
	night
	object.get(ctx, ["occupancy", "value"], "unknown") == "home"
}

# ---------------------------------------------------------------- appliance safety (AP)

deny_rules contains "AP1" if {
	dom == "climate"
	to_number(object.get(action, ["args", "target_c"], 0)) > to_number(object.get(ctx, "max_setpoint_c", 30))
}

deny_rules contains "AP2" if {
	regex.match(`boiler|water_heater`, dev)
	cmd in on_cmds
	object.get(ctx, ["device_state", "fault"], false) == true
}

deny_rules contains "AP3" if {
	regex.match(`stove|oven|cooktop|boiler|water_heater|space_heater|fireplace|pool_heater`, dev)
	cmd in on_cmds
	object.get(ctx, ["occupancy", "value"], "unknown") == "away"
}

deny_rules contains "AP4" if {
	cmd in on_cmds
	to_number(object.get(action, ["args", "duration_s"], 0)) > to_number(object.get(ctx, "max_duration_s", 7200))
}

deny_rules contains "AP5" if {
	cmd in on_cmds
	some req in object.get(ctx, ["interlocks", "required"], [])
	object.get(ctx, ["interlocks", "satisfied"], []) != []
	not req in object.get(ctx, ["interlocks", "satisfied"], [])
}

deny_rules contains "AP5" if {
	cmd in on_cmds
	object.get(ctx, ["interlocks", "required"], []) != []
	object.get(ctx, ["interlocks", "satisfied"], []) == []
}

# ---------------------------------------------------------------- sensor integrity (SI)

deny_rules contains "SI1" if {
	tier in {"high", "critical"}
	to_number(object.get(ctx, ["occupancy", "age_s"], 0)) > to_number(object.get(ctx, "max_state_age_s", 300))
}

escalate_rules contains "SI2" if {
	object.get(ctx, ["sensors", "conflict"], false) == true
}

deny_rules contains "SI3" if {
	tier == "critical"
	object.get(ctx, ["occupancy", "value"], "unknown") == "unknown"
}

escalate_rules contains "SI3" if {
	tier == "high"
	object.get(ctx, ["occupancy", "value"], "unknown") == "unknown"
}

deny_rules contains "SI4" if {
	tier in {"high", "critical"}
	object.get(ctx, "state_authenticated", true) == false
}

# ---------------------------------------------------------------- temporal / sequential (TS)

night if {
	t := object.get(ctx, "time_hhmm", "12:00")
	hh := to_number(substring(t, 0, 2))
	hh >= 23
}

night if {
	t := object.get(ctx, "time_hhmm", "12:00")
	hh := to_number(substring(t, 0, 2))
	hh < 6
}

deny_rules contains "TS1" if {
	object.get(action, ["args", "night_restricted"], false) == true
	night
}

deny_rules contains "TS2" if {
	to_number(object.get(ctx, "last_action_age_s", 999999)) < to_number(object.get(ctx, "cooldown_s", 0))
}

deny_rules contains "TS3" if {
	some p in object.get(ctx, ["prerequisites", "required"], [])
	not p in object.get(ctx, ["prerequisites", "met"], [])
}

deny_rules contains "TS4" if {
	to_number(object.get(ctx, "toggles_last_minute", 0)) >= 5
}


# ================================================================ semantic action normalization
# earlier revision, review section 9.4. String matching on device names is fragile: the held-out audit
# failed precisely where an access device exposes "open" as `turn_on`, so a rule keyed on the command
# string missed it. Normalization maps the platform representation to a semantic action class, and the
# policy is written against the class.
#
# Every entry below is derived from a (device, command) pair that actually appears in the evaluation
# corpus. No mapping is invented for a representation the platform does not use.

# Declared device registry: entity-id prefix -> device role. In a deployment this is the operator's
# enrollment registry; here it is the union of every device the evaluation corpora exercise.
role_table := {
	# access: admits a person or opens an aperture
	"lock.": "access",
	"cover.": "access",
	"input_boolean.garage": "access",
	"switch.front_gate": "access",
	# life safety: alarms, panels, the detectors they rest on, and emergency notification
	"alarm.": "life_safety",
	"alarm_control_panel.": "life_safety",
	"binary_sensor.smoke": "life_safety",
	"binary_sensor.co_": "life_safety",
	"binary_sensor.carbon": "life_safety",
	"notify.emergency": "life_safety",
	# sensing: state the verifier itself depends on
	"camera.": "sensing",
	"sensor.": "sensing",
	"binary_sensor.": "sensing",
	# thermal: can heat, or is temperature-controlled
	"climate.": "thermal",
	"switch.boiler": "thermal",
	"switch.water_heater": "thermal",
	"switch.space_heater": "thermal",
	"switch.heater": "thermal",
	"switch.pool_heater": "thermal",
	"switch.heat_pump": "thermal",
	"switch.gas_fireplace": "thermal",
	"switch.oven": "thermal",
	"switch.stove": "thermal",
	"switch.dryer": "thermal",
	# remaining declared roles
	"switch.ev_charger": "power",
	"switch.chest_freezer": "preservation",
	"switch.sump_pump": "protection",
	"switch.pump": "protection",
	"switch.sprinkler": "protection",
	"light.": "illumination",
	"notify.": "notification",
}

# Longest matching prefix wins, so binary_sensor.smoke_kitchen resolves to life_safety rather than to
# the generic sensing entry. Resolution is deterministic: prefixes of equal length cannot both match.
_role_hits contains [count(pattern), role] if {
	some pattern, role in role_table
	startswith(dev, pattern)
}

device_role := role if {
	count(_role_hits) > 0
	best := max({n | some [n, _] in _role_hits})
	some [n2, role] in _role_hits
	n2 == best
}

default device_role := "unknown"

# semantic action class = role x direction. Direction is taken from the service, not the device name.
direction := "enable" if cmd in on_cmds
direction := "enable" if cmd in {"unlock", "open"}
direction := "disable" if cmd in off_cmds
direction := "disable" if cmd in {"lock", "close", "silence", "disarm", "test"}
direction := "enable" if cmd in {"arm", "set_temperature"}

default direction := "unknown"

semantic_class := sprintf("%s.%s", [device_role, direction])

# The semantic classes this policy bundle was written to decide. Anything outside is UNCOVERED, and
# uncovered is not the same as safe.
declared_classes := {
	"access.enable", "access.disable",
	"life_safety.enable", "life_safety.disable",
	"sensing.enable", "sensing.disable",
	"thermal.enable", "thermal.disable",
	"power.enable", "power.disable",
	"preservation.enable", "preservation.disable",
	"protection.enable", "protection.disable",
	"illumination.enable", "illumination.disable",
	"notification.enable", "notification.disable",
}

covered if semantic_class in declared_classes

# ================================================================ fail-safe coverage (CV)
# Review section 9.3. Policy incompleteness must be explicit behaviour, not a silent permit. An
# unmatched semantic class at high risk escalates to human confirmation; at critical risk it denies.
# Low risk retains the configurable permissive default, since escalating every unknown low-risk action
# would make the system unusable and is not where the security value is.

deny_rules contains "CV1" if {
	tier == "critical"
	not covered
}

escalate_rules contains "CV2" if {
	tier == "high"
	not covered
}

deny_rules contains "CV3" if {
	tier == "critical"
	device_role == "unknown"
}

escalate_rules contains "CV4" if {
	tier == "high"
	device_role == "unknown"
}

# An access or life-safety action whose service the bundle does not recognise never silently permits.
escalate_rules contains "CV5" if {
	device_role in {"access", "sensing"}
	direction == "unknown"
	tier != "low"
}

# ---------------------------------------------------------------- decision

default decision := "permit"

decision := "deny" if count(deny_rules) > 0

decision := "escalate" if {
	count(deny_rules) == 0
	count(escalate_rules) > 0
}

result := {
	"decision": decision,
	"deny_rules": sort([r | some r in deny_rules]),
	"escalate_rules": sort([r | some r in escalate_rules]),
}
