"""Action plugins for automated response."""

from .base import Action, BaseAction
from .block_ip import BlockIPAction
from .isolate_host import IsolateHostAction
from .notify_webhook import NotifyWebhookAction

__all__ = [
    "Action",
    "BaseAction",
    "BlockIPAction",
    "IsolateHostAction",
    "NotifyWebhookAction",
]
