"""Registry of all rules."""

from nti_scanner.rules.nti.identity import IdentityRule
from nti_scanner.rules.nti.governance import GovernanceRule
from nti_scanner.rules.nti.consensus import ConsensusRule
from nti_scanner.rules.nti.audit import AuditRule
from nti_scanner.rules.nti.persistence import PersistenceRule
from nti_scanner.rules.nti.capability_diff import CapabilityDiffRule
from nti_scanner.rules.nti.trust_boundary import TrustBoundaryRule

from nti_scanner.rules.security.prompt_injection import PromptInjectionRule
from nti_scanner.rules.security.command_injection import CommandInjectionRule
from nti_scanner.rules.security.path_traversal import PathTraversalRule
from nti_scanner.rules.security.ssrf import SSRRule
from nti_scanner.rules.security.sql_injection import SQLInjectionRule
from nti_scanner.rules.security.secret_leak import SecretLeakRule
from nti_scanner.rules.security.unsafe_deserialization import UnsafeDeserializationRule
from nti_scanner.rules.security.capability_escalation import CapabilityEscalationRule
from nti_scanner.rules.security.llm_trust import LLMTrustRule
from nti_scanner.rules.security.mcp_rules import MCPRule
from nti_scanner.rules.security.a2a_rules import A2ARule
from nti_scanner.rules.security.pqc_readiness import PQCReadinessRule


RULES = [
    IdentityRule(),
    GovernanceRule(),
    ConsensusRule(),
    AuditRule(),
    PersistenceRule(),
    CapabilityDiffRule(),
    TrustBoundaryRule(),
    PromptInjectionRule(),
    CommandInjectionRule(),
    PathTraversalRule(),
    SSRRule(),
    SQLInjectionRule(),
    SecretLeakRule(),
    UnsafeDeserializationRule(),
    CapabilityEscalationRule(),
    LLMTrustRule(),
    MCPRule(),
    A2ARule(),
    PQCReadinessRule(),
]


def get_rules_for_context(frameworks):
    return RULES
