"""Security gate scanners for ControlGate."""

from controlgate.gates.aiml_gate import AIMLGate
from controlgate.gates.api_gate import APIGate
from controlgate.gates.audit_gate import AuditGate
from controlgate.gates.change_gate import ChangeGate
from controlgate.gates.container_gate import ContainerGate
from controlgate.gates.crypto_gate import CryptoGate
from controlgate.gates.deps_gate import DepsGate
from controlgate.gates.iac_gate import IaCGate
from controlgate.gates.iam_gate import IAMGate
from controlgate.gates.incident_gate import IncidentGate
from controlgate.gates.input_gate import InputGate
from controlgate.gates.license_gate import LicenseGate
from controlgate.gates.memsafe_gate import MemSafeGate
from controlgate.gates.observability_gate import ObservabilityGate
from controlgate.gates.privacy_gate import PrivacyGate
from controlgate.gates.resilience_gate import ResilienceGate
from controlgate.gates.sbom_gate import SBOMGate
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
    ResilienceGate,
    IncidentGate,
    ObservabilityGate,
    MemSafeGate,
    LicenseGate,
    AIMLGate,
    ContainerGate,
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
    "ResilienceGate",
    "IncidentGate",
    "ObservabilityGate",
    "MemSafeGate",
    "LicenseGate",
    "AIMLGate",
    "ContainerGate",
    "ALL_GATES",
]
