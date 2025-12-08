"""Action plugins for automated response."""

from .base import Action, BaseAction
from .block_ip import BlockIPAction
from .isolate_host import IsolateHostAction
from .notify_webhook import NotifyWebhookAction
from .terminate_process import TerminateProcessAction
from .quarantine_network import QuarantineNetworkAction
from .disable_account import DisableAccountAction
from .collect_artifacts import CollectArtifactsAction

__all__ = [
    "Action",
    "BaseAction",
    "BlockIPAction",
    "IsolateHostAction",
    "NotifyWebhookAction",
    "TerminateProcessAction",
    "QuarantineNetworkAction",
    "DisableAccountAction",
    "CollectArtifactsAction",
]
