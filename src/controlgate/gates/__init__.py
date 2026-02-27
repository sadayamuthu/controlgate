"""Security gate scanners for ControlGate."""

from controlgate.gates.api_gate import APIGate
from controlgate.gates.audit_gate import AuditGate
from controlgate.gates.change_gate import ChangeGate
from controlgate.gates.crypto_gate import CryptoGate
from controlgate.gates.deps_gate import DepsGate
from controlgate.gates.iac_gate import IaCGate
from controlgate.gates.iam_gate import IAMGate
from controlgate.gates.input_gate import InputGate
from controlgate.gates.sbom_gate import SBOMGate
from controlgate.gates.privacy_gate import PrivacyGate
from controlgate.gates.secrets_gate import SecretsGate

ALL_GATES = [
    SecretsGate,
    CryptoGate,
    IAMGate,
    SBOMGate,
    IaCGate,
    InputGate,
    AuditGate,
    ChangeGate,
    DepsGate,
    APIGate,
    PrivacyGate,
]

__all__ = [
    "SecretsGate",
    "CryptoGate",
    "IAMGate",
    "SBOMGate",
    "IaCGate",
    "InputGate",
    "AuditGate",
    "ChangeGate",
    "DepsGate",
    "APIGate",
    "PrivacyGate",
    "ALL_GATES",
]
