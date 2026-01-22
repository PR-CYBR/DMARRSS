"""Action plugins for automated response."""

from .base import Action, BaseAction
from .block_ip import BlockIPAction
from .collect_artifacts import CollectArtifactsAction
from .disable_account import DisableAccountAction
from .isolate_host import IsolateHostAction
from .notify_webhook import NotifyWebhookAction
from .quarantine_network import QuarantineNetworkAction
from .terminate_process import TerminateProcessAction

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
