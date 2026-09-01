"""AgentGuard — A local runtime security layer for AI agents."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("agentguard")
except PackageNotFoundError:  # pragma: no cover
    __version__ = "0.0.0-dev"
