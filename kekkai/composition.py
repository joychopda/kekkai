"""The composition root: the one place concrete implementations are chosen and wired.

Every other module receives its collaborators. This is Main-as-plugin -- it depends on all
four rings, and nothing depends on it.
"""

from __future__ import annotations

from .adapters.audit_sink import JsonlAuditSink
from .adapters.classifiers import get_backend
from .adapters.langchain_host import GuardrailMiddleware
from .application.cache import DecisionCache
from .application.ports import AuditSinkPort, ClassifierPort
from .application.screen_tool_call import ScreenToolCall
from .config import KekkaiConfig


def build_classifier(config: KekkaiConfig) -> ClassifierPort:
    return get_backend(config.backend)()


def build_sink(config: KekkaiConfig) -> AuditSinkPort:
    return JsonlAuditSink(config.log_dir, fsync_policy=config.fsync_policy)


def build_screener(
    config: KekkaiConfig,
    *,
    classifier: ClassifierPort | None = None,
    sink: AuditSinkPort | None = None,
) -> ScreenToolCall:
    return ScreenToolCall(
        classifier or build_classifier(config),
        sink or build_sink(config),
        policy=config.policy,
        cache=DecisionCache(config.cache_size),
        workspace_root=config.workspace_root,
        egress_allowlist=config.egress_allowlist,
    )


async def build_middleware(
    config: KekkaiConfig | None = None,
    *,
    session_id: str = "",
    warmup: bool = True,
) -> GuardrailMiddleware:
    """Build the LangChain middleware, pre-warming the backend by default.

    Warm-up matters: a first inference carries lazy graph compilation, and skipping it charges
    a multi-second penalty to whichever real tool call happens to arrive first.
    """
    config = config or KekkaiConfig.load()
    screener = build_screener(config)
    if warmup:
        await screener.warmup()
    return GuardrailMiddleware(screener, session_id=session_id)
