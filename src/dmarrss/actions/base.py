"""
Base action interface for DMARRSS response plugins.
"""

import uuid
from abc import ABC, abstractmethod
from typing import Protocol

from ..schemas import ActionResult, Decision


class Action(Protocol):
    """
    Action protocol for response plugins.

    All action plugins must implement this interface.
    """

    name: str

    def execute(self, decision: Decision, dry_run: bool = True) -> ActionResult:
        """
        Execute the action.

        Args:
            decision: Decision object with threat details
            dry_run: If True, only log what would be done (default)

        Returns:
            ActionResult with execution details
        """
        ...


class BaseAction(ABC):
    """
    Base class for action plugins.

    Provides common functionality for dry-run and logging.
    """

    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    def _execute_impl(self, decision: Decision) -> ActionResult:
        """
        Implementation of the action.

        Subclasses must implement this method.
        Should only be called when dry_run=False.
        """
        pass

    @abstractmethod
    def _dry_run_impl(self, decision: Decision) -> ActionResult:
        """
        Dry-run implementation.

        Subclasses must implement this method.
        Should log what would be done without executing.
        """
        pass

    def execute(self, decision: Decision, dry_run: bool = True) -> ActionResult:
        """
        Execute the action with dry-run support.

        Args:
            decision: Decision object
            dry_run: If True, only log planned actions

        Returns:
            ActionResult
        """
        if dry_run:
            return self._dry_run_impl(decision)
        else:
            return self._execute_impl(decision)

    def _create_result(
        self,
        decision: Decision,
        success: bool,
        dry_run: bool,
        executed: bool,
        message: str,
        details: dict = None,
        error: str = None,
    ) -> ActionResult:
        """Helper to create ActionResult"""
        return ActionResult(
            action_id=str(uuid.uuid4()),
            decision_id=decision.decision_id,
            action_name=self.name,
            success=success,
            dry_run=dry_run,
            executed=executed,
            message=message,
            details=details or {},
            error=error,
        )
