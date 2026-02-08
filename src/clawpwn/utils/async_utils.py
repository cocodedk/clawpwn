"""Async utilities for safe subprocess and event loop management."""

import asyncio
import gc
import signal
import sys
import threading
import warnings
from collections.abc import Coroutine
from typing import Any, TypeVar, cast

T = TypeVar("T")

# Track active subprocess transports for cleanup
_active_transports: set[asyncio.SubprocessTransport] = set()


def register_transport(transport: asyncio.SubprocessTransport) -> None:
    """Register a subprocess transport for cleanup tracking."""
    _active_transports.add(transport)


def unregister_transport(transport: asyncio.SubprocessTransport) -> None:
    """Unregister a subprocess transport."""
    _active_transports.discard(transport)


def _close_transports() -> None:
    """Close all tracked subprocess transports."""
    for transport in list(_active_transports):
        try:
            if not transport.is_closing():
                transport.close()
        except Exception:
            pass
    _active_transports.clear()


def _cancel_all_tasks(loop: asyncio.AbstractEventLoop) -> None:
    """Cancel all pending tasks on the event loop."""
    tasks = asyncio.all_tasks(loop)
    for task in tasks:
        task.cancel()

    if tasks:
        loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))


def _shutdown_asyncgens(loop: asyncio.AbstractEventLoop) -> None:
    """Shutdown all async generators."""
    try:
        loop.run_until_complete(loop.shutdown_asyncgens())
    except Exception:
        pass


def _shutdown_default_executor(loop: asyncio.AbstractEventLoop) -> None:
    """Shutdown the default executor."""
    try:
        loop.run_until_complete(loop.shutdown_default_executor())
    except Exception:
        pass


def _run_in_fresh_loop[T](coro: Coroutine[Any, Any, T]) -> T:
    """Run an async coroutine in a new loop with subprocess-safe cleanup."""
    if sys.platform == "win32":
        # Windows needs ProactorEventLoop for subprocess support
        loop = asyncio.ProactorEventLoop()
    else:
        loop = asyncio.new_event_loop()

    asyncio.set_event_loop(loop)

    # Store original signal handlers
    original_sigint = None
    original_sigterm = None
    interrupted = False

    def signal_handler(signum: int, frame: Any) -> None:
        nonlocal interrupted
        interrupted = True
        # Cancel all tasks gracefully
        for task in asyncio.all_tasks(loop):
            task.cancel()

    # Install signal handlers only on Unix main thread.
    if sys.platform != "win32" and threading.current_thread() is threading.main_thread():
        original_sigint = signal.signal(signal.SIGINT, signal_handler)
        original_sigterm = signal.signal(signal.SIGTERM, signal_handler)

    try:
        return loop.run_until_complete(coro)
    except asyncio.CancelledError:
        if interrupted:
            raise KeyboardInterrupt from None
        raise
    finally:
        try:
            _cancel_all_tasks(loop)
            _close_transports()
            _shutdown_asyncgens(loop)
            _shutdown_default_executor(loop)
        finally:
            # Run GC before closing loop to clean up subprocess transports
            gc.collect()
            asyncio.set_event_loop(None)
            loop.close()

        # Restore original signal handlers
        if sys.platform != "win32" and threading.current_thread() is threading.main_thread():
            if original_sigint is not None:
                signal.signal(signal.SIGINT, original_sigint)
            if original_sigterm is not None:
                signal.signal(signal.SIGTERM, original_sigterm)


def safe_async_run[T](coro: Coroutine[Any, Any, T]) -> T:
    """
    Run an async coroutine with proper cleanup of subprocesses.

    If an event loop is already running in this thread (e.g. pytest-asyncio),
    the coroutine is executed in a separate thread with its own event loop.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return _run_in_fresh_loop(coro)

    result: T | None = None
    error: BaseException | None = None

    def _runner() -> None:
        nonlocal result, error
        try:
            result = _run_in_fresh_loop(coro)
        except BaseException as exc:
            error = exc

    thread = threading.Thread(target=_runner, daemon=True)
    thread.start()
    thread.join()

    if error is not None:
        raise error

    return cast(T, result)


def suppress_event_loop_closed_error() -> None:
    """
    Suppress the 'Event loop is closed' RuntimeError from subprocess __del__.

    Call this at program startup to prevent the error from being printed.
    """
    # Filter out the specific warning/error
    warnings.filterwarnings(
        "ignore",
        message=".*Event loop is closed.*",
        category=RuntimeWarning,
    )
