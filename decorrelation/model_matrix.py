"""Domain-labelled local-model matrix for RQ1 (spec §4). Only installed Ollama tags. Includes a
quant-variant pair (same family+params, different quantization) as the quantization/runtime domain probe."""
from __future__ import annotations
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class ModelConfig:
    tag: str
    family: str
    params: float   # billions
    quant: str      # e.g. "default", "q8_0"


MATRIX = [
    ModelConfig("llama3.1:8b", "llama", 8.0, "default"),
    ModelConfig("llama3.2:3b", "llama", 3.0, "default"),
    ModelConfig("llama3.2:3b-instruct-q8_0", "llama", 3.0, "q8_0"),   # quant-variant pair with llama3.2:3b
    ModelConfig("qwen2.5:7b", "qwen", 7.6, "default"),
    ModelConfig("qwen2.5:3b", "qwen", 3.0, "default"),
    ModelConfig("mistral:7b", "mistral", 7.2, "default"),
    ModelConfig("mistral-nemo:12b", "mistral", 12.0, "default"),
    ModelConfig("gemma3:4b", "gemma", 4.3, "default"),
    ModelConfig("gemma2:9b", "gemma", 9.0, "default"),
    ModelConfig("phi4-mini:latest", "phi", 3.8, "default"),
    ModelConfig("phi3.5:3.8b", "phi", 3.8, "default"),
    ModelConfig("granite3.1-dense:8b", "granite", 8.0, "default"),
    ModelConfig("granite3.1-moe:3b", "granite", 3.0, "default"),
]


def installed_tags() -> set[str]:
    out = subprocess.run(["ollama", "list"], capture_output=True, text=True, timeout=30).stdout
    tags = set()
    for line in out.splitlines()[1:]:
        if line.strip():
            tags.add(line.split()[0])
    return tags


def validate_matrix(installed: set[str]) -> list[str]:
    return [m.tag for m in MATRIX if m.tag not in installed]
