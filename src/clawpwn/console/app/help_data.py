"""Aggregated help data for ConsoleApp."""

from .help_aliases import HELP_TOPIC_ALIASES
from .help_topics_primary import HELP_TOPICS_PRIMARY
from .help_topics_secondary import HELP_TOPICS_SECONDARY

HELP_TOPICS: dict[str, str] = {
    **HELP_TOPICS_PRIMARY,
    **HELP_TOPICS_SECONDARY,
}

__all__ = ["HELP_TOPIC_ALIASES", "HELP_TOPICS"]
