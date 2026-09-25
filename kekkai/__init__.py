"""KekkAI — a pre-execution guardrail for AI agent tool calls.

The decision engine lives in `kekkai.domain` and `kekkai.application` and depends on
nothing but the standard library. Classifier backends and agent-framework integrations are
adapters in `kekkai.adapters`, installed as extras.
"""

__version__ = "0.1.0"
