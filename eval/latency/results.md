# Task 5 latency results — feasibility on a capable hub (Apple M4)

> dec_01KVWZV01Z23GWW41451NH96X6: M4-only, **emulated** Home Assistant actuation. These numbers show feasibility on a capable hub; they are **not** representative of a constrained home device, and no physical actuation occurs.

liboqs 0.15.0; ML-DSA via FIPS-204 params; means over 300 iters (end-to-end over 50).

## ML-DSA sign/verify (the PQC provenance primitive)

| Param set | pk (B) | sig (B) | sign mean (ms) | sign median (ms) | verify mean (ms) | verify median (ms) |
|-----------|-------:|--------:|---------------:|-----------------:|-----------------:|-------------------:|
| ML-DSA-44 | 1312 | 2420 | 0.168 | 0.125 | 0.039 | 0.039 |
| ML-DSA-65 | 1952 | 3309 | 0.261 | 0.210 | 0.063 | 0.062 |
| ML-DSA-87 | 2592 | 4627 | 0.322 | 0.265 | 0.102 | 0.100 |

## Tamper-evident log

Merkle commit + inclusion-proof verify (ML-DSA-65 leaf): mean 0.317 ms, median 0.256 ms.

## End-to-end provenance -> emulated actuation (ML-DSA-65), by stage

| Stage | mean (ms) |
|-------|----------:|
| OPA/Rego guard (subprocess) | 18.344 |
| ML-DSA sign | 0.321 |
| Merkle commit | 0.061 |
| verify (sig + inclusion) | 0.131 |
| emulated actuation | 0.004 |
| **total** | **18.861** |
| total excl. OPA cold-start subprocess | 0.517 |

**Note:** the OPA guard latency is dominated by per-call CLI process start-up; a long-running OPA server (or the Go/Rust OPA SDK) removes it. The crypto+log+verify core is well under a typical smart-home actuation responsiveness budget on this hub.
