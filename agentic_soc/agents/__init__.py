"""The five agents of the multi-agent design (blueprint section 14).

| Agent                     | Input                      | Output                               |
|---------------------------|----------------------------|--------------------------------------|
| TriageAgent               | Wazuh alert / incident     | Severity, confidence, classification |
| InvestigationAgent        | Alert + historical context | Related alerts / entities            |
| ThreatIntelAgent          | IPs, domains, hashes       | Reputation / CTI evidence            |
| CorrelationAgent          | Multiple alerts            | Incident-level narrative             |
| ResponseAgent             | Incident context           | Recommended approved action          |
"""

from agentic_soc.agents.correlation_agent import CorrelationAgent
from agentic_soc.agents.enrichment_agent import StaticThreatIntel, ThreatIntelAgent
from agentic_soc.agents.investigation_agent import InvestigationAgent
from agentic_soc.agents.response_agent import ResponseAgent
from agentic_soc.agents.triage_agent import TriageAgent

__all__ = [
    "CorrelationAgent",
    "InvestigationAgent",
    "ResponseAgent",
    "StaticThreatIntel",
    "ThreatIntelAgent",
    "TriageAgent",
]
