from __future__ import annotations

import logging
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_FALLBACK_BIN_DIR = Path.home() / ".local" / "bin"


def _resolve_binary(name: str) -> str | None:
    """Return the full path for *name*, trying PATH then ~/.local/bin."""
    path = shutil.which(name)
    if path:
        return path
    fallback = _FALLBACK_BIN_DIR / name
    if fallback.is_file():
        return str(fallback)
    return None


class SubdomainEnumerator:
    """Enumerates subdomains using subfinder and amass in parallel."""

    def __init__(self, config: dict[str, Any], tool_manager: Any = None) -> None:
        self.config = config
        self.tool_manager = tool_manager

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, target: str) -> list[str]:
        """Run subfinder and amass in parallel; return sorted unique subdomains."""
        results: list[str] = []
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = {
                executor.submit(self._run_subfinder, target): "subfinder",
                executor.submit(self._run_amass, target): "amass",
            }
            for future in as_completed(futures):
                tool = futures[future]
                try:
                    domains = future.result()
                    results.extend(domains)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Unexpected error collecting results from %s: %s", tool, exc)

        return sorted(set(results))

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _run_subfinder(self, target: str) -> list[str]:
        """Run ``subfinder -d {target} -silent`` and return found domains."""
        binary = _resolve_binary("subfinder")
        if not binary:
            logger.warning("subfinder not found on PATH or ~/.local/bin; skipping")
            return []

        cmd = [binary, "-d", target, "-silent"]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            if proc.returncode != 0:
                logger.warning(
                    "subfinder exited with code %d for target %s: %s",
                    proc.returncode,
                    target,
                    proc.stderr[:200],
                )
                return []
            return [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        except subprocess.TimeoutExpired:
            logger.warning("subfinder timed out for target %s", target)
            return []
        except FileNotFoundError:
            logger.warning("subfinder binary not found: %s", binary)
            return []
        except Exception as exc:  # noqa: BLE001
            logger.warning("subfinder error for target %s: %s", target, exc)
            return []

    def _run_amass(self, target: str) -> list[str]:
        """Run ``amass enum -passive -d {target} -silent`` and return found domains."""
        binary = _resolve_binary("amass")
        if not binary:
            logger.warning("amass not found on PATH or ~/.local/bin; skipping")
            return []

        cmd = [binary, "enum", "-passive", "-d", target, "-silent"]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            if proc.returncode != 0:
                logger.warning(
                    "amass exited with code %d for target %s: %s",
                    proc.returncode,
                    target,
                    proc.stderr[:200],
                )
                return []
            return [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        except subprocess.TimeoutExpired:
            logger.warning("amass timed out for target %s", target)
            return []
        except FileNotFoundError:
            logger.warning("amass binary not found: %s", binary)
            return []
        except Exception as exc:  # noqa: BLE001
            logger.warning("amass error for target %s: %s", target, exc)
            return []
