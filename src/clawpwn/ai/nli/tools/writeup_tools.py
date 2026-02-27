"""Tool schema for writeup generation."""

from typing import Any

GENERATE_WRITEUP_TOOL: dict[str, Any] = {
    "name": "generate_writeup",
    "description": (
        "Generate a narrative task writeup summarizing what was done, "
        "what was found, and conclusions. Call this after a scan or attack "
        "plan completes. The writeup is saved to the database and written "
        "as a markdown file in the project's writeups/ directory."
    ),
    "input_schema": {
        "type": "object",
        "properties": {},
        "required": [],
    },
}
