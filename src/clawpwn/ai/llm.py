"""LLM client for ClawPwn AI integration."""

import os
from typing import Optional, List, Dict, Any
from pathlib import Path

import httpx

from clawpwn.config import (
    get_api_key,
    get_config,
    create_project_config_template,
    create_global_config,
)


class LLMClient:
    """Client for interacting with LLM APIs (Claude, GPT-4, etc.)."""

    def __init__(
        self,
        provider: str = "anthropic",
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        project_dir: Optional[Path] = None,
    ):
        self.provider = provider.lower()
        self.project_dir = project_dir

        # Get API key from multiple sources
        if api_key:
            self.api_key = api_key
        else:
            self.api_key = self._get_api_key_with_fallback()

        # Default models
        self.model = model or {
            "anthropic": "claude-3-5-sonnet-20241022",
            "openai": "gpt-4o",
        }.get(self.provider, "claude-3-5-sonnet-20241022")

        self.client = httpx.Client(timeout=60.0)

    def _get_api_key_with_fallback(self) -> str:
        """Get API key from multiple sources with helpful error messages."""
        api_key = get_api_key(self.provider, self.project_dir)

        if not api_key:
            # Create helpful error message with setup instructions
            env_var = {
                "anthropic": "ANTHROPIC_API_KEY",
                "openai": "OPENAI_API_KEY",
            }.get(self.provider, f"{self.provider.upper()}_API_KEY")

            error_msg = f"""API key not found for provider: {self.provider}

To set your API key, choose one of these methods:

1. Environment variable (quick):
   export {env_var}=your-api-key

2. Project .env file (recommended per project):
   echo "{env_var}=your-api-key" >> .clawpwn/.env

3. Global config file:
   echo "{env_var}: your-api-key" >> ~/.clawpwn/config.yml

Get your API key from:
- Anthropic: https://console.anthropic.com/
- OpenAI: https://platform.openai.com/
"""
            raise ValueError(error_msg)

        return api_key

    def chat(self, message: str, system_prompt: Optional[str] = None) -> str:
        """Send a chat message and get a response."""
        if self.provider == "anthropic":
            return self._chat_anthropic(message, system_prompt)
        elif self.provider == "openai":
            return self._chat_openai(message, system_prompt)
        else:
            raise ValueError(f"Unknown provider: {self.provider}")

    def _chat_anthropic(self, message: str, system_prompt: Optional[str] = None) -> str:
        """Chat with Claude API."""
        url = "https://api.anthropic.com/v1/messages"

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

        payload: Dict[str, Any] = {
            "model": self.model,
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": message}],
        }

        if system_prompt:
            payload["system"] = system_prompt

        response = self.client.post(url, headers=headers, json=payload)
        response.raise_for_status()

        data = response.json()
        return data["content"][0]["text"]

    def _chat_openai(self, message: str, system_prompt: Optional[str] = None) -> str:
        """Chat with OpenAI API."""
        url = "https://api.openai.com/v1/chat/completions"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": message})

        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": 4096,
        }

        response = self.client.post(url, headers=headers, json=payload)
        response.raise_for_status()

        data = response.json()
        return data["choices"][0]["message"]["content"]

    def analyze_finding(self, finding_data: Dict[str, Any]) -> str:
        """Analyze a finding and provide AI insights."""
        system_prompt = """You are a penetration testing expert. Analyze the finding and provide:
1. A clear explanation of the vulnerability
2. Potential impact and risk
3. Remediation steps
Be concise and technical."""

        message = f"Analyze this finding:\n\n{str(finding_data)}"
        return self.chat(message, system_prompt)

    def suggest_next_steps(
        self, current_phase: str, findings: List[Dict[str, Any]]
    ) -> str:
        """Suggest next steps in the pentest based on current state."""
        system_prompt = """You are a penetration testing strategist. Based on the current phase and findings, suggest the next logical steps in the kill chain. Be specific and actionable."""

        message = f"Current phase: {current_phase}\n\nFindings so far:\n{str(findings)}\n\nWhat should I do next?"
        return self.chat(message, system_prompt)
