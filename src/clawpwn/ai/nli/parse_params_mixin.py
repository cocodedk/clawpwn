"""Parsing and parameter helpers for NLI."""

import json
import re
from typing import Any


class ParseParamsMixin:
    """Helpers for parsing LLM responses and parameter payloads."""

    def _parse_intent_response(self, response: str) -> dict[str, str]:
        result = {"intent": "unknown", "target": "", "parameters": "", "confidence": "low"}
        for line in response.strip().split("\n"):
            if line.startswith("INTENT:"):
                result["intent"] = line.replace("INTENT:", "").strip().lower()
            elif line.startswith("TARGET:"):
                result["target"] = line.replace("TARGET:", "").strip()
            elif line.startswith("PARAMETERS:"):
                result["parameters"] = line.replace("PARAMETERS:", "").strip()
            elif line.startswith("CONFIDENCE:"):
                result["confidence"] = line.replace("CONFIDENCE:", "").strip().lower()
        return result

    def _parse_action_response(self, response: str) -> dict[str, Any]:
        result: dict[str, Any] = {
            "intent": "",
            "target": "",
            "parameters": "",
            "params": {},
            "confidence": "low",
            "needs_input": False,
            "question": "",
        }
        text = response.strip()
        if not text:
            return result

        if text.startswith("{"):
            try:
                data = json.loads(text)
                if isinstance(data, dict):
                    result["intent"] = str(data.get("action") or data.get("intent") or "").strip()
                    result["target"] = str(data.get("target") or "").strip()
                    result["params"] = self._normalize_params(data.get("params") or {})
                    result["confidence"] = str(data.get("confidence") or "low").lower()
                    result["needs_input"] = bool(data.get("needs_input") or False)
                    result["question"] = str(data.get("question") or "").strip()
                    return result
            except Exception:
                pass

        for line in text.splitlines():
            if line.startswith("ACTION:"):
                result["intent"] = line.replace("ACTION:", "").strip().lower()
            elif line.startswith("INTENT:"):
                result["intent"] = line.replace("INTENT:", "").strip().lower()
            elif line.startswith("TARGET:"):
                result["target"] = line.replace("TARGET:", "").strip()
            elif line.startswith("PARAMS:"):
                raw = line.replace("PARAMS:", "").strip()
                result["params"] = self._parse_params(raw)
            elif line.startswith("PARAMETERS:"):
                result["parameters"] = line.replace("PARAMETERS:", "").strip()
            elif line.startswith("CONFIDENCE:"):
                result["confidence"] = line.replace("CONFIDENCE:", "").strip().lower()
            elif line.startswith("NEEDS_INPUT:"):
                value = line.replace("NEEDS_INPUT:", "").strip().lower()
                result["needs_input"] = value in {"yes", "true", "1"}
            elif line.startswith("QUESTION:"):
                result["question"] = line.replace("QUESTION:", "").strip()
        return result

    def _normalize_params(self, params: Any) -> dict[str, Any]:
        if not isinstance(params, dict):
            return {}
        normalized: dict[str, Any] = {}
        for key, value in params.items():
            if key is None:
                continue
            k = str(key)
            k = re.sub(r"([a-z])([A-Z])", r"\1_\2", k)
            k = k.replace("-", "_").replace(" ", "_").lower()
            normalized[k] = value
        return normalized

    def _parse_params(self, raw: str) -> dict[str, Any]:
        if not raw:
            return {}
        if raw.startswith("{") or raw.startswith("["):
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    return self._normalize_params(parsed)
                return {"value": parsed}
            except Exception:
                return {}
        params: dict[str, Any] = {}
        for part in raw.split(","):
            if "=" in part:
                k, v = part.split("=", 1)
                params[k.strip()] = v.strip()
        return self._normalize_params(params)

    def _get_params(self, parsed: dict[str, Any]) -> dict[str, Any]:
        params = parsed.get("params")
        if isinstance(params, dict):
            return self._normalize_params(params)
        raw = parsed.get("parameters")
        if isinstance(raw, str) and raw:
            return self._parse_params(raw)
        return {}

    def _param_str(self, params: dict[str, Any], key: str, default: str) -> str:
        value = params.get(key, default)
        if isinstance(value, str) and value:
            return value.strip().lower()
        return default

    def _param_int(self, params: dict[str, Any], key: str, default: int) -> int:
        value = params.get(key, default)
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _param_bool(self, params: dict[str, Any], key: str, default: bool) -> bool:
        value = params.get(key, default)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on"}
        return default
