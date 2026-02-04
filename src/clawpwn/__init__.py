"""ClawPwn package."""

__all__ = ["app", "main"]


def __getattr__(name: str):
    if name in __all__:
        from clawpwn.cli import app, main

        return {"app": app, "main": main}[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(__all__)
