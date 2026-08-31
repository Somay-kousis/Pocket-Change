"""Test-wide isolation.

Every gateway built in a test gets its own root key. Without this the persisted
key is shared, two gateways verify each other's tokens, and a forgery test
quietly stops testing forgery - which is exactly what happened when key
persistence was added: the assertion moved from 401 forged to 404 unknown
mandate and would have gone unnoticed if the suite had not been re-run.

Tests must also never write a key to the repository.
"""

import os

import pytest

from tests._operator import OPERATOR_TOKEN


@pytest.fixture(autouse=True)
def ephemeral_keys(monkeypatch):
    monkeypatch.setenv("POCKETCHANGE_EPHEMERAL_KEYS", "1")


@pytest.fixture(autouse=True)
def operator_credential(monkeypatch):
    """The gateway refuses operator routes when this is unset, so set it."""
    monkeypatch.setenv("POCKETCHANGE_OPERATOR_TOKEN", OPERATOR_TOKEN)


@pytest.fixture(autouse=True, scope="session")
def never_read_dotenv():
    """Stop config.load() undoing the scrubbing below.

    It is called again inside every model invocation, so clearing the
    environment was not enough: a test that believed it was offline would have
    its credentials restored from .env and quietly reach the network.
    """
    os.environ["POCKETCHANGE_NO_DOTENV"] = "1"
    yield
    os.environ.pop("POCKETCHANGE_NO_DOTENV", None)


@pytest.fixture(autouse=True)
def no_cloud(monkeypatch):
    """No credentials in tests, so nothing reaches Firestore, Razorpay or Gemini."""
    for name in (
        "GOOGLE_CLOUD_PROJECT",
        "RAZORPAY_KEY_ID",
        "RAZORPAY_KEY_SECRET",
        "GOOGLE_API_KEY",
        "GEMINI_API_KEY",
        # The fallback providers. Omitting these was not hypothetical: adding the
        # fallback chain immediately turned two "the model is unreachable" tests
        # into live calls to Groq, which passed for the wrong reason and put the
        # suite back on the network.
        "GROQ_API_KEY",
        "OPENROUTER_API_KEY",
        "CEREBRAS_API_KEY",
        "SAMBANOVA_API_KEY",
        "TAVILY_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
