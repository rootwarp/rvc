import importlib.util
import json
import sys
import threading
from pathlib import Path

import pytest
from pytest_socket import disable_socket

def _script_path(name: str) -> Path:
    return Path(__file__).resolve().parents[1] / f"{name}.py"


SCRIPT = _script_path("validator_perf")
_FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _no_network():
    disable_socket()  # no ini file exists, so no addopts; do it here


@pytest.fixture(autouse=True)
def xdg_cache_home(tmp_path, monkeypatch):
    # Isolate the P2-3 index cache; never touch the real ~/.cache (SM3).
    cache_home = tmp_path / "xdg-cache"
    monkeypatch.setenv("XDG_CACHE_HOME", str(cache_home))
    return cache_home


def load_script(name: str = "validator_perf"):
    path = _script_path(name)
    # Unique module aliases (validator_perf_guard) still load validator_perf.py.
    if not path.is_file():
        path = SCRIPT
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise FileNotFoundError(path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)  # requires the __main__ guard
    return mod


@pytest.fixture(scope="session")
def vp():
    return load_script()


@pytest.fixture(scope="session")
def dr():
    return load_script("devnet_report")


@pytest.fixture
def load():
    return lambda name: json.loads((_FIXTURES / f"{name}.json").read_text())


def raw_response(vp, name: str, status: int = 200, truncated: bool = False):
    body = (_FIXTURES / f"{name}.json").read_bytes()
    return vp.RawResponse(status, body, truncated)


def raw_text(mod, name: str, status: int = 200):
    body = (_FIXTURES / f"{name}.txt").read_bytes()
    return mod.RawResponse(status, body)


def route_map(**scenarios):
    """Build FakeTransport routes. Keys are 'METHOD path'."""
    routes: dict[tuple[str, str], list] = {}
    for key, responses in scenarios.items():
        method, path = key.split(None, 1)
        routes[(method, path)] = list(responses)
    return routes


def concurrent_failures(n: int, item, *, timeout: float = 5.0):
    """N callers wait at a barrier, then each yields `item`.

    Harness capability (VP-4a / VP-4d): first N in-flight calls all fail
    together so workers observe the dying endpoint simultaneously.
    `item` is a RawResponse, an exception instance, or a callable.
    """
    barrier = threading.Barrier(n, timeout=timeout)

    def once():
        barrier.wait()
        if isinstance(item, BaseException):
            raise item
        if callable(item):
            return item()
        return item

    return [once for _ in range(n)]


class FakeTransport:
    def __init__(self, routes: dict[tuple, list]):
        self.routes = {key: list(queue) for key, queue in routes.items()}
        self.calls: list[tuple[str, str, str, object]] = []
        self.drops: list = []
        self.closed = False
        self._lock = threading.Lock()

    def __call__(self, ep, method, path, body):
        # Pop under the lock; invoke callables after release so a barrier
        # in concurrent_failures cannot deadlock against this lock.
        with self._lock:
            self.calls.append((ep.label, method, path, body))
            queue = self.routes.get((ep.label, method, path))
            if queue is None:
                queue = self.routes.get((method, path))
            if queue is None:
                # Exact (method, path) wins. Bare-path fallback is only GET
                # .../validators?id= chunks (RD-1); other queried routes stay exact.
                if method == "GET" and "?" in path:
                    bare = path.split("?", 1)[0]
                    if bare.endswith("/validators"):
                        queue = self.routes.get((ep.label, method, bare))
                        if queue is None:
                            queue = self.routes.get((method, bare))
            if queue is None:
                raise KeyError(
                    f"unscripted FakeTransport call: {method} {path}"
                ) from None
            if not queue:
                raise IndexError(f"no scripted responses left for {method} {path}")
            item = queue.pop(0)
        if callable(item):
            return item()
        return item

    def drop(self, ep):
        self.drops.append(ep)

    def close(self):
        self.closed = True
