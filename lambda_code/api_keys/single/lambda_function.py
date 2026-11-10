"""Dispatch one provider-specific Secrets Manager API-key rotation Lambda."""

import logging
import os

import boto3
import openai_keys
import openai_rotation
import openrouter_keys
import openrouter_rotation


LOG = logging.getLogger(__name__)
LOG.setLevel(logging.INFO)
PROVIDERS = {
    openai_keys.NAME: openai_rotation,
    openrouter_keys.NAME: openrouter_rotation,
}


def lambda_handler(event, context):
    """Handle one of Secrets Manager's rotation steps without logging secrets."""
    del context
    try:
        rotate(event, boto3.client("secretsmanager"))
    except Exception as exc:
        provider = os.environ.get("API_PROVIDER", "unknown")
        provider = provider if provider in PROVIDERS else "unknown"
        step = event.get("Step") if isinstance(event, dict) else None
        step = step if step in (
            "createSecret", "setSecret", "testSecret", "finishSecret", "reconcileOrphan"
        ) else "unknown"
        LOG.error("API key rotation failed: provider=%s step=%s error_type=%s",
                  provider, step, type(exc).__name__)
        raise RuntimeError("API key rotation failed") from None


def rotate(event, secrets):
    provider = os.environ["API_PROVIDER"]
    if provider not in PROVIDERS:
        raise ValueError("Unsupported API provider")
    PROVIDERS[provider].rotate(event, secrets)
