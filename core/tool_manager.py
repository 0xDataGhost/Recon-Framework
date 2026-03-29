"""
core/tool_manager.py — detect and auto-install required recon tools.

Installation strategy (tried in order):
  1. PATH / config tool_paths override  — already installed, nothing to do
  2. ~/.local/bin/                       — previously installed by this manager
  3. go install <module>@latest          — if Go is available
  4. GitHub Releases binary download     — primary fallback (works without Go)

All tools are from the projectdiscovery suite or known GitHub projects and
have predictable release asset naming conventions.

Platform support: linux/darwin × amd64/arm64.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import tempfile
import zipfile
import tarfile
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.exceptions import ToolInstallError, ToolNotAvailableError


# ── Platform helpers ───────────────────────────────────────────────────────────

def _platform_tag() -> tuple[str, str]:
    """Return (os_name, arch) suitable for GitHub release asset names."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    os_name = {"darwin": "darwin", "linux": "linux"}.get(system, system)

    if machine in ("arm64", "aarch64"):
        arch = "arm64"
    elif machine in ("x86_64", "amd64"):
        arch = "amd64"
    else:
        arch = machine

    return os_name, arch


_OS, _ARCH = _platform_tag()
_LOCAL_BIN = Path.home() / ".local" / "bin"


# ── Tool registry ──────────────────────────────────────────────────────────────

@dataclass
class _ToolSpec:
    """Static metadata for one tool."""
    name: str
    go_module: str          # e.g. "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
    gh_owner: str           # GitHub owner
    gh_repo: str            # GitHub repo
    # asset name template — placeholders: {os}, {arch}, {version}
    # leave empty to auto-derive from common projectdiscovery pattern
    asset_template: str = ""
    # override binary name inside archive if different from tool name
    binary_name: str = ""

    def resolve_binary_name(self) -> str:
        return self.binary_name or self.name


_TOOLS: dict[str, _ToolSpec] = {
    "subfinder": _ToolSpec(
        name="subfinder",
        go_module="github.com/projectdiscovery/subfinder/v2/cmd/subfinder",
        gh_owner="projectdiscovery",
        gh_repo="subfinder",
    ),
    "amass": _ToolSpec(
        name="amass",
        go_module="github.com/owasp-amass/amass/v4/...",
        gh_owner="owasp-amass",
        gh_repo="amass",
        # amass assets use "amass_linux_amd64.zip" style
        asset_template="amass_{os}_{arch}.zip",
        binary_name="amass",
    ),
    "httpx": _ToolSpec(
        name="httpx",
        go_module="github.com/projectdiscovery/httpx/cmd/httpx",
        gh_owner="projectdiscovery",
        gh_repo="httpx",
    ),
    "naabu": _ToolSpec(
        name="naabu",
        go_module="github.com/projectdiscovery/naabu/v2/cmd/naabu",
        gh_owner="projectdiscovery",
        gh_repo="naabu",
    ),
    "nuclei": _ToolSpec(
        name="nuclei",
        go_module="github.com/projectdiscovery/nuclei/v3/cmd/nuclei",
        gh_owner="projectdiscovery",
        gh_repo="nuclei",
    ),
    "gau": _ToolSpec(
        name="gau",
        go_module="github.com/lc/gau/v2/cmd/gau",
        gh_owner="lc",
        gh_repo="gau",
        # gau assets: "gau_2.2.1_macOS_arm64.tar.gz"
        asset_template="gau_{version}_{os_cap}_{arch}.tar.gz",
        binary_name="gau",
    ),
    "waybackurls": _ToolSpec(
        name="waybackurls",
        go_module="github.com/tomnomnom/waybackurls",
        gh_owner="tomnomnom",
        gh_repo="waybackurls",
        asset_template="waybackurls-{os}-{arch}-{version}.tgz",
        binary_name="waybackurls",
    ),
    "ffuf": _ToolSpec(
        name="ffuf",
        go_module="github.com/ffuf/ffuf/v2",
        gh_owner="ffuf",
        gh_repo="ffuf",
        # ffuf assets: "ffuf_2.1.0_linux_amd64.tar.gz"
        asset_template="ffuf_{version}_{os}_{arch}.tar.gz",
        binary_name="ffuf",
    ),
}


# ── ToolStatus ─────────────────────────────────────────────────────────────────

@dataclass
class ToolStatus:
    """Result of checking whether one tool is available."""
    name: str
    installed: bool
    version: str | None = None
    path: str | None = None
    error: str | None = None


# ── ToolManager ────────────────────────────────────────────────────────────────

class ToolManager:
    """
    Detect and auto-install required recon tools.

    Args:
        config: Loaded framework config dict. May contain:
            ``tool_paths`` (dict[str, str]) — absolute path overrides per tool.
            ``tool_install_dir`` (str) — override install directory (default ~/.local/bin).

    Example::

        tm = ToolManager(config)
        statuses = tm.check_all()
        for name, status in statuses.items():
            if not status.installed:
                tm.ensure_tool(name)
        path = tm.get_tool_path("httpx")
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config
        self._tool_paths: dict[str, str] = config.get("tool_paths", {})
        install_dir = config.get("tool_install_dir", str(_LOCAL_BIN))
        self._install_dir = Path(install_dir).expanduser().resolve()
        # cache of resolved paths found during check_all()
        self._resolved: dict[str, str] = {}

    # ── Public API ─────────────────────────────────────────────────────────────

    def check_all(self) -> dict[str, ToolStatus]:
        """
        Check availability of every registered tool.

        Returns:
            Ordered dict mapping tool name → :class:`ToolStatus`.
        """
        return {name: self._check_one(name) for name in _TOOLS}

    def ensure_tool(self, name: str) -> str:
        """
        Ensure *name* is available, installing it if necessary.

        Returns:
            Absolute path to the installed binary.

        Raises:
            ToolNotAvailableError: If the tool is unknown.
            ToolInstallError:      If installation fails via all methods.
        """
        if name not in _TOOLS:
            raise ToolNotAvailableError(name, reason=f"'{name}' is not in the tool registry")

        status = self._check_one(name)
        if status.installed and status.path:
            return status.path

        return self._install(name)

    def get_tool_path(self, name: str) -> str:
        """
        Return the absolute path to *name*.

        Checks the cache populated by :meth:`check_all` or :meth:`ensure_tool`
        first, then falls back to a fresh PATH probe.

        Raises:
            ToolNotAvailableError: If the tool cannot be found.
        """
        if name in self._resolved:
            return self._resolved[name]
        status = self._check_one(name)
        if status.installed and status.path:
            return status.path
        raise ToolNotAvailableError(
            name,
            reason="not found on PATH and not installed; run --install-tools",
        )

    # ── Internal: detection ───────────────────────────────────────────────────

    def _check_one(self, name: str) -> ToolStatus:
        """Probe PATH + install dir + config overrides for *name*."""
        spec = _TOOLS.get(name)
        if spec is None:
            return ToolStatus(name=name, installed=False, error="unknown tool")

        # 1. Config override
        if name in self._tool_paths:
            override = Path(self._tool_paths[name]).expanduser()
            if override.is_file() and os.access(override, os.X_OK):
                version = self._get_version(str(override), name)
                self._resolved[name] = str(override)
                return ToolStatus(name=name, installed=True, version=version, path=str(override))

        # 2. ~/.local/bin (our install dir)
        local_path = self._install_dir / spec.resolve_binary_name()
        if local_path.is_file() and os.access(local_path, os.X_OK):
            version = self._get_version(str(local_path), name)
            self._resolved[name] = str(local_path)
            return ToolStatus(name=name, installed=True, version=version, path=str(local_path))

        # 3. System PATH
        which = shutil.which(spec.resolve_binary_name())
        if which:
            version = self._get_version(which, name)
            self._resolved[name] = which
            return ToolStatus(name=name, installed=True, version=version, path=which)

        return ToolStatus(name=name, installed=False)

    @staticmethod
    def _get_version(binary_path: str, tool_name: str) -> str | None:
        """Run ``<binary> --version`` and return the first line, or None."""
        try:
            result = subprocess.run(
                [binary_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = (result.stdout or result.stderr or "").strip()
            return output.splitlines()[0] if output else None
        except Exception:
            return None

    # ── Internal: installation ────────────────────────────────────────────────

    def _install(self, name: str) -> str:
        """
        Attempt installation via go install, then GitHub Releases.

        Returns the path to the installed binary on success.

        Raises:
            ToolInstallError: If all methods fail.
        """
        spec = _TOOLS[name]
        errors: list[str] = []

        # Ensure install dir exists
        try:
            self._install_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ToolInstallError(
                name,
                reason=f"Cannot create install directory {self._install_dir}: {exc}",
            ) from exc

        # Method 1: go install
        go_bin = shutil.which("go")
        if go_bin:
            try:
                return self._go_install(name, spec, go_bin)
            except ToolInstallError as exc:
                errors.append(f"go install: {exc.context.get('reason', str(exc))}")

        # Method 2: GitHub Releases
        try:
            return self._github_install(name, spec)
        except ToolInstallError as exc:
            errors.append(f"github release: {exc.context.get('reason', str(exc))}")

        raise ToolInstallError(
            name,
            reason="; ".join(errors) or "all installation methods failed",
            context={"methods_tried": ["go_install", "github_release"]},
        )

    def _go_install(self, name: str, spec: _ToolSpec, go_bin: str) -> str:
        """Install via ``go install <module>@latest``."""
        env = os.environ.copy()
        # ensure our install dir is in GOBIN so the binary lands there
        env["GOBIN"] = str(self._install_dir)

        cmd = [go_bin, "install", f"{spec.go_module}@latest"]
        try:
            result = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            raise ToolInstallError(
                name,
                reason="go install timed out after 300s",
                context={"command": " ".join(cmd)},
            )
        except Exception as exc:
            raise ToolInstallError(
                name,
                reason=f"go install subprocess error: {exc}",
                context={"command": " ".join(cmd)},
            ) from exc

        if result.returncode != 0:
            raise ToolInstallError(
                name,
                reason=f"go install exited {result.returncode}",
                context={
                    "command": " ".join(cmd),
                    "stderr": (result.stderr or "")[:500],
                },
            )

        installed_path = self._install_dir / spec.resolve_binary_name()
        if installed_path.exists():
            self._resolved[name] = str(installed_path)
            return str(installed_path)

        # go may have installed to GOPATH/bin — try to find and copy
        gopath_bin = Path(
            subprocess.run(
                [go_bin, "env", "GOPATH"],
                capture_output=True, text=True
            ).stdout.strip()
        ) / "bin" / spec.resolve_binary_name()

        if gopath_bin.exists():
            dest = self._install_dir / spec.resolve_binary_name()
            shutil.copy2(str(gopath_bin), str(dest))
            dest.chmod(dest.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
            self._resolved[name] = str(dest)
            return str(dest)

        raise ToolInstallError(
            name,
            reason="go install succeeded but binary not found in GOBIN or GOPATH/bin",
        )

    def _github_install(self, name: str, spec: _ToolSpec) -> str:
        """Download and extract the latest binary from GitHub Releases."""
        # Step 1: get latest release tag + asset list from GitHub API
        tag, assets = self._get_latest_release_info(name, spec)

        # Step 2: pick the best-matching asset for this platform
        url = self._pick_asset_url(name, spec, tag, assets)

        # Step 3: download
        archive_path = self._download(name, url)

        # Step 4: extract
        binary_dest = self._install_dir / spec.resolve_binary_name()
        try:
            self._extract_binary(archive_path, spec.resolve_binary_name(), binary_dest)
        finally:
            try:
                archive_path.unlink()
            except OSError:
                pass

        if not binary_dest.exists():
            raise ToolInstallError(
                name,
                reason=f"binary '{spec.resolve_binary_name()}' not found in archive {asset_name}",
                context={"archive": asset_name, "url": url},
            )

        binary_dest.chmod(
            binary_dest.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH
        )
        self._resolved[name] = str(binary_dest)
        return str(binary_dest)

    def _get_latest_release_info(
        self, name: str, spec: _ToolSpec
    ) -> tuple[str, list[dict[str, Any]]]:
        """
        Query GitHub API for the latest release tag and its asset list.

        Returns:
            (tag_name, list_of_asset_dicts)  where each asset dict has at
            minimum ``browser_download_url`` and ``name`` keys.
        """
        api_url = f"https://api.github.com/repos/{spec.gh_owner}/{spec.gh_repo}/releases/latest"
        try:
            req = urllib.request.Request(
                api_url,
                headers={
                    "Accept": "application/vnd.github+json",
                    "User-Agent": "recon-framework/0.1",
                },
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data: dict[str, Any] = json.loads(resp.read().decode())
            tag: str = data["tag_name"]
            assets: list[dict[str, Any]] = data.get("assets", [])
            return tag, assets
        except (urllib.error.URLError, KeyError, json.JSONDecodeError) as exc:
            raise ToolInstallError(
                name,
                reason=f"failed to fetch latest release from GitHub: {exc}",
                context={"api_url": api_url},
            ) from exc

    def _pick_asset_url(
        self,
        name: str,
        spec: _ToolSpec,
        tag: str,
        assets: list[dict[str, Any]],
    ) -> str:
        """
        Select the download URL for the current platform from the asset list.

        Scoring: prefers exact OS+arch matches in the asset filename.
        Falls back to the guessed template URL if the asset list is empty.
        """
        version = tag.lstrip("v")
        os_cap = _OS.capitalize()

        # Platform tokens to look for (ordered most-specific first)
        os_tokens = [_OS, os_cap, "macos" if _OS == "darwin" else _OS]
        arch_tokens = [_ARCH, "arm64" if _ARCH == "arm64" else _ARCH]

        # Archive extensions we can handle
        valid_exts = (".zip", ".tar.gz", ".tgz")

        best_url: str | None = None
        best_score = -1

        for asset in assets:
            asset_name: str = asset.get("name", "")
            url: str = asset.get("browser_download_url", "")
            if not url or not any(asset_name.endswith(e) for e in valid_exts):
                continue
            low = asset_name.lower()
            score = 0
            for tok in os_tokens:
                if tok.lower() in low:
                    score += 2
                    break
            for tok in arch_tokens:
                if tok.lower() in low:
                    score += 2
                    break
            # Prefer files that contain the tool name
            if name.lower() in low:
                score += 1
            if score > best_score:
                best_score = score
                best_url = url

        if best_url and best_score >= 3:
            return best_url

        # Fallback: build a guessed URL using the asset template or default convention
        if spec.asset_template:
            asset_name_guess = spec.asset_template.format(
                os=_OS, os_cap=os_cap, arch=_ARCH,
                version=version, tag=tag, name=name,
            )
        else:
            asset_name_guess = f"{name}_{version}_{_OS}_{_ARCH}.zip"

        fallback_url = (
            f"https://github.com/{spec.gh_owner}/{spec.gh_repo}"
            f"/releases/download/{tag}/{asset_name_guess}"
        )

        # If we found something (even with low score), prefer it over a guessed URL
        if best_url:
            return best_url

        return fallback_url

    def _download(self, name: str, url: str) -> Path:
        """Download *url* to a temporary file; return its Path."""
        suffix = Path(url).suffix  # .zip / .tar.gz / .tgz — last component only
        # preserve double extension for .tar.gz
        url_path = url.split("?")[0]
        if url_path.endswith(".tar.gz"):
            suffix = ".tar.gz"
        elif url_path.endswith(".tgz"):
            suffix = ".tgz"
        else:
            suffix = Path(url_path).suffix or ".bin"

        tmp_fd, tmp_path = tempfile.mkstemp(prefix=f"recon_{name}_", suffix=suffix)
        os.close(tmp_fd)
        dest = Path(tmp_path)

        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "recon-framework/0.1"},
            )
            with urllib.request.urlopen(req, timeout=120) as resp, dest.open("wb") as fh:
                shutil.copyfileobj(resp, fh)
        except urllib.error.HTTPError as exc:
            dest.unlink(missing_ok=True)
            raise ToolInstallError(
                name,
                reason=f"HTTP {exc.code} downloading {url}",
                context={"url": url, "http_status": exc.code},
            ) from exc
        except urllib.error.URLError as exc:
            dest.unlink(missing_ok=True)
            raise ToolInstallError(
                name,
                reason=f"network error downloading {url}: {exc.reason}",
                context={"url": url},
            ) from exc

        return dest

    @staticmethod
    def _extract_binary(archive: Path, binary_name: str, dest: Path) -> None:
        """
        Extract *binary_name* from *archive* (zip / tar.gz / tgz) to *dest*.

        Searches all entries in the archive for a file whose name (ignoring
        directory prefix) matches *binary_name*.
        """
        archive_str = str(archive)

        if archive_str.endswith(".zip"):
            with zipfile.ZipFile(archive_str) as zf:
                for entry in zf.infolist():
                    entry_name = Path(entry.filename).name
                    if entry_name == binary_name and not entry.filename.endswith("/"):
                        with zf.open(entry) as src, dest.open("wb") as dst:
                            shutil.copyfileobj(src, dst)
                        return

        elif archive_str.endswith((".tar.gz", ".tgz")):
            with tarfile.open(archive_str, "r:gz") as tf:
                for member in tf.getmembers():
                    if Path(member.name).name == binary_name and member.isfile():
                        extracted = tf.extractfile(member)
                        if extracted:
                            with dest.open("wb") as dst:
                                shutil.copyfileobj(extracted, dst)
                        return

        else:
            # Assume the download IS the binary (some tools ship a plain binary)
            shutil.copy2(archive_str, str(dest))
