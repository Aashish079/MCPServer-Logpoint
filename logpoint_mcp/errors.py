"""Exception hierarchy.

Messages are shown to the LLM (FastMCP turns an exception into a tool error), so
they must explain what went wrong and must never contain credentials.
"""


class LogpointMCPError(Exception):
    """Base class for every error raised by this package."""


class LogpointError(LogpointMCPError):
    """Logpoint could not be reached or returned an unusable response."""


class LogpointAuthError(LogpointError):
    """Logpoint rejected the configured credentials."""


class LogpointAPIError(LogpointError):
    """Logpoint answered, but reported a failure (`"success": false`, HTTP error, bad body)."""


class LogpointSearchError(LogpointAPIError):
    """A search was rejected (e.g. query syntax error) or failed while running."""


class NotFoundError(LogpointMCPError):
    """The requested object (incident, user, repo, ...) does not exist."""


class IntegrationError(LogpointMCPError):
    """A third-party integration (VirusTotal, AbuseIPDB, MISP, Jira, SMTP, MITRE) failed."""
