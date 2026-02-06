"""Composed help topics and aliases."""

from clawpwn.ai.nli.help_topic_aliases import HELP_TOPIC_ALIASES
from clawpwn.ai.nli.help_topics_core import HELP_TOPICS_CORE
from clawpwn.ai.nli.help_topics_ops import HELP_TOPICS_OPS

HELP_TOPICS: dict[str, str] = {**HELP_TOPICS_CORE, **HELP_TOPICS_OPS}

__all__ = ["HELP_TOPICS", "HELP_TOPIC_ALIASES"]
