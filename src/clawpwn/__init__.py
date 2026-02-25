"""ClawPwn package."""

__all__ = ["app", "main"]


def _patch_subprocess_transport() -> None:
    """
    Patch asyncio subprocess transport to suppress 'Event loop is closed' error.

    This is a known Python issue where subprocess transports garbage collected
    after the event loop closes raise RuntimeError in their __del__ method.
    """
    import asyncio.base_subprocess

    _original_del = asyncio.base_subprocess.BaseSubprocessTransport.__del__

    def _patched_del(self):
        try:
            _original_del(self)
        except RuntimeError as e:
            if "Event loop is closed" not in str(e):
                raise

    asyncio.base_subprocess.BaseSubprocessTransport.__del__ = _patched_del


# Apply patch on import
_patch_subprocess_transport()


def __getattr__(name: str):
    if name in __all__:
        from clawpwn.cli import app, main

        return {"app": app, "main": main}[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(__all__)
