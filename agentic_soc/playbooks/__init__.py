from agentic_soc.models.schemas import ResponseAction
from agentic_soc.playbooks.base import Playbook, PlaybookContext, ResponseServices
from agentic_soc.playbooks.block_ip import BlockIPPlaybook
from agentic_soc.playbooks.collect_evidence import CollectEvidencePlaybook
from agentic_soc.playbooks.disable_user import DisableUserPlaybook
from agentic_soc.playbooks.isolate_host import IsolateHostPlaybook

PLAYBOOKS: dict[ResponseAction, type[Playbook]] = {
    ResponseAction.ISOLATE_HOST: IsolateHostPlaybook,
    ResponseAction.BLOCK_IP: BlockIPPlaybook,
    ResponseAction.DISABLE_USER: DisableUserPlaybook,
    ResponseAction.COLLECT_EVIDENCE: CollectEvidencePlaybook,
}


def build_playbooks(services: ResponseServices) -> dict[ResponseAction, Playbook]:
    return {action: cls(services) for action, cls in PLAYBOOKS.items()}


__all__ = ["PLAYBOOKS", "Playbook", "PlaybookContext", "ResponseServices", "build_playbooks"]
