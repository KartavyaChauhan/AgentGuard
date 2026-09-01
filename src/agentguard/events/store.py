"""In-memory event store for tracking session events."""

from __future__ import annotations

from typing import Iterable, TYPE_CHECKING

from agentguard.events.models import ToolEvent
from agentguard.logging import get_logger

if TYPE_CHECKING:
    from agentguard.audit.repository import AuditRepository

logger = get_logger(__name__)

class EventStore:
    """An in-memory, session-aware store for ToolEvents.

    Maintains chronologically ordered lists of events per session, isolating
    events between sessions.
    """

    def __init__(self, audit_repository: AuditRepository | None = None) -> None:
        self._events_by_session: dict[str, list[ToolEvent]] = {}
        self._events_by_id: dict[str, ToolEvent] = {}
        self._audit_repository = audit_repository

    def record(self, event: ToolEvent) -> None:
        """Record a new event into the store.

        Parameters
        ----------
        event:
            The immutable ToolEvent to store.
        """
        if event.session_id not in self._events_by_session:
            self._events_by_session[event.session_id] = []
        
        self._events_by_session[event.session_id].append(event)
        self._events_by_id[event.event_id] = event
        
        if self._audit_repository:
            from agentguard.audit.models import create_audit_event_from_tool_event
            from agentguard.audit.database import AuditPersistenceError
            
            # We need the previous event's hash to chain correctly
            prev_hash = None
            if len(self._events_by_session[event.session_id]) > 1:
                prev_event_id = self._events_by_session[event.session_id][-2].event_id
                # Get the actual persisted audit event to get its hash
                try:
                    recent = self._audit_repository.get_session_events(event.session_id)
                    if recent:
                        prev_hash = recent[-1].event_hash
                except AuditPersistenceError as e:
                    logger.error(f"Failed to fetch previous hash from audit repository: {e}")
                    
            try:
                audit_event = create_audit_event_from_tool_event(event, prev_hash)
                self._audit_repository.append(audit_event)
            except AuditPersistenceError as e:
                logger.error(f"Failed to append to audit repository (side-channel isolated): {e}")

    def get(self, event_id: str) -> ToolEvent | None:
        """Fetch a specific event by its ID.

        Returns
        -------
        ToolEvent | None
            The event if found, else None.
        """
        return self._events_by_id.get(event_id)

    def get_session_events(self, session_id: str) -> list[ToolEvent]:
        """Fetch all events for a session in chronological insertion order.

        Returns a shallow copy of the list to prevent external mutation of the
        internal data structure.

        Returns
        -------
        list[ToolEvent]
            Chronological list of events for the session.
        """
        # Return a copy of the list to protect internal state
        return list(self._events_by_session.get(session_id, []))

    def recent_events(self, session_id: str, limit: int) -> list[ToolEvent]:
        """Fetch the most recent events for a session, up to `limit`.

        Returns a shallow copy.

        Returns
        -------
        list[ToolEvent]
            Chronological list of the most recent events.
        """
        if limit < 0:
            raise ValueError("limit must be non-negative")
        
        events = self._events_by_session.get(session_id, [])
        if limit == 0 or not events:
            return []
        
        # Return a slice (which creates a copy)
        return events[-limit:]

    def count(self, session_id: str) -> int:
        """Count the number of events in a session."""
        return len(self._events_by_session.get(session_id, []))

    def clear(self, session_id: str) -> None:
        """Clear all events for a specific session."""
        if session_id in self._events_by_session:
            events = self._events_by_session.pop(session_id)
            # Remove from ID index
            for e in events:
                self._events_by_id.pop(e.event_id, None)
