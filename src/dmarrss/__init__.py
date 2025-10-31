"""
DMARRSS - Decentralized Machine Assisted Rapid Response Security System

An autonomous security pipeline for continuous threat detection and response.
"""

__version__ = "1.0.0"
__author__ = "PR-CYBR"

from .schemas import ActionResult, Decision, Event  # noqa: F401

__all__ = ["Event", "Decision", "ActionResult", "__version__"]
