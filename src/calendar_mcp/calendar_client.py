"""Google Calendar API wrapper with security constraints."""

import logging

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

from calendar_mcp.security import sanitize_calendar_content, sanitize_event_content

logger = logging.getLogger("calendar-mcp.client")


class CalendarClient:
    """Thin wrapper around the Google Calendar API, enforcing security constraints."""

    def __init__(self, credentials: Credentials) -> None:
        self._service = build("calendar", "v3", credentials=credentials)

    def list_calendars(self) -> list[dict]:
        """List all calendars accessible by the user.

        Calendar names and descriptions from shared calendars are untrusted
        content and are sanitized to prevent prompt injection.
        """
        result = self._service.calendarList().list().execute()
        calendars = []
        for cal in result.get("items", []):
            entry = {
                "id": cal["id"],
                "summary": cal.get("summary", ""),
                "description": cal.get("description", ""),
                "primary": cal.get("primary", False),
                "access_role": cal.get("accessRole", ""),
                "time_zone": cal.get("timeZone", ""),
            }
            calendars.append(sanitize_calendar_content(entry))
        return calendars

    def get_events(
        self,
        calendar_id: str = "primary",
        time_min: str | None = None,
        time_max: str | None = None,
        max_results: int = 50,
        query: str | None = None,
    ) -> list[dict]:
        """Retrieve events within a time range. All event content is sanitized."""
        kwargs: dict = {
            "calendarId": calendar_id,
            "maxResults": max_results,
            "singleEvents": True,
            "orderBy": "startTime",
        }
        if time_min:
            kwargs["timeMin"] = time_min
        if time_max:
            kwargs["timeMax"] = time_max
        if query:
            kwargs["q"] = query

        result = self._service.events().list(**kwargs).execute()
        events = []
        for event in result.get("items", []):
            parsed = self._parse_event(event)
            events.append(sanitize_event_content(parsed))
        return events

    def get_event(self, event_id: str, calendar_id: str = "primary") -> dict:
        """Retrieve a single event by ID. Content is sanitized."""
        event = self._service.events().get(calendarId=calendar_id, eventId=event_id).execute()
        parsed = self._parse_event(event)
        return sanitize_event_content(parsed)

    def get_freebusy(
        self,
        calendars: list[str],
        time_min: str,
        time_max: str,
    ) -> dict:
        """Check free/busy availability without exposing event details."""
        body = {
            "timeMin": time_min,
            "timeMax": time_max,
            "items": [{"id": cal_id} for cal_id in calendars],
        }
        result = self._service.freebusy().query(body=body).execute()

        freebusy_data = {}
        for cal_id, cal_data in result.get("calendars", {}).items():
            freebusy_data[cal_id] = {
                "busy": cal_data.get("busy", []),
                "errors": [e.get("reason", "") for e in cal_data.get("errors", [])],
            }

        return {
            "time_min": result.get("timeMin", time_min),
            "time_max": result.get("timeMax", time_max),
            "calendars": freebusy_data,
        }

    def create_event(
        self,
        summary: str,
        start_time: str,
        end_time: str,
        calendar_id: str = "primary",
        description: str | None = None,
        location: str | None = None,
        timezone: str = "UTC",
        attendees: list[str] | None = None,
        send_updates: str = "none",
    ) -> dict:
        """Create a calendar event.

        Attendees and notifications are controlled by the server, not the caller.
        The caller passes pre-validated values from the security layer.
        """
        event: dict = {
            "summary": summary,
            "start": {"dateTime": start_time, "timeZone": timezone},
            "end": {"dateTime": end_time, "timeZone": timezone},
        }

        if description:
            event["description"] = description
        if location:
            event["location"] = location
        if attendees:
            event["attendees"] = [{"email": email} for email in attendees]

        # NO conferenceData — prevents auto-generated Meet links that could leak

        created = (
            self._service.events()
            .insert(
                calendarId=calendar_id,
                body=event,
                sendUpdates=send_updates,
            )
            .execute()
        )

        return {
            "id": created["id"],
            "summary": created.get("summary", ""),
            "start": created.get("start", {}),
            "end": created.get("end", {}),
            "html_link": created.get("htmlLink", ""),
            "status": created.get("status", ""),
        }

    def delete_event(
        self,
        event_id: str,
        calendar_id: str = "primary",
    ) -> dict:
        """Delete a calendar event. Does not send cancellation notifications."""
        self._service.events().delete(
            calendarId=calendar_id,
            eventId=event_id,
            sendUpdates="none",
        ).execute()
        return {"deleted": True, "event_id": event_id}

    # -- Internal helpers --

    def _parse_event(self, event: dict) -> dict:
        """Extract relevant fields from a Calendar API event response."""
        organizer = event.get("organizer", {})
        organizer_str = organizer.get("email", organizer.get("displayName", ""))

        parsed: dict = {
            "id": event.get("id", ""),
            "status": event.get("status", ""),
            "summary": event.get("summary", "(no title)"),
            "start": event.get("start", {}),
            "end": event.get("end", {}),
        }

        if event.get("description"):
            parsed["description"] = event["description"]
        if event.get("location"):
            parsed["location"] = event["location"]
        if organizer_str:
            parsed["organizer"] = organizer_str

        # Attendee fields are attacker-controlled — wrap in delimiters
        attendees = event.get("attendees", [])
        if attendees:
            parsed["attendees"] = [
                {
                    "email": (
                        f"<attendee_email>{a['email']}</attendee_email>" if a.get("email") else ""
                    ),
                    "response_status": a.get("responseStatus", ""),
                    "display_name": (
                        f"<attendee_name>{a['displayName']}</attendee_name>"
                        if a.get("displayName")
                        else ""
                    ),
                }
                for a in attendees
            ]

        # Conference info (read-only)
        conference = event.get("conferenceData", {})
        entry_points = conference.get("entryPoints", [])
        if entry_points:
            parsed["conference"] = [
                {
                    "type": ep.get("entryPointType", ""),
                    "uri": ep.get("uri", ""),
                }
                for ep in entry_points
            ]

        parsed["created"] = event.get("created", "")
        parsed["updated"] = event.get("updated", "")
        parsed["html_link"] = event.get("htmlLink", "")

        return parsed
