#!/usr/bin/env python3
"""
HunterV2 — Multi-Agent Vulnerability Orchestrator
===================================================

Architecture inspired by Agent Orchestrator (AO):
  • Each agent runs as an **isolated subprocess** with its own workspace
  • A central **message bus** coordinates findings and deduplicates work
  • The **orchestrator daemon** monitors health, restarts crashed agents,
    and aggregates results into a live Kanban-style status board
  • Agents communicate via a shared **multiprocessing queue** so one agent's
    discovery can inform or redirect another

Usage:
    python orchestrator.py --target https://example.com --confirm-authorized
    python orchestrator.py --target https://example.com --confirm-authorized --vulns xss sqli ssrf
    python orchestrator.py --target https://example.com --confirm-authorized --workers 8 --max-depth 10
"""

import argparse
import json
import logging
import multiprocessing
import os
import queue
import signal
import sys
import time
import traceback
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from multiprocessing import Process, Queue, Event, Manager
from pathlib import Path
from typing import Optional


# Configure UTF-8 for console output on Windows to prevent UnicodeEncodeError
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


# --------------------------------------------------------------------------
# Config / Logging
# --------------------------------------------------------------------------

def _setup_logging(agent_id: str = "orchestrator", log_dir: Path = None):
    """Create a per-agent logger that writes to both console and file."""
    logger = logging.getLogger(agent_id)
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    # File handler (per-agent log)
    if log_dir:
        log_dir.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_dir / f"{agent_id}.log", encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger


RESULTS_DIR = Path("./results")
WORKSPACE_DIR = Path("./workspaces")


# --------------------------------------------------------------------------
# Data Models
# --------------------------------------------------------------------------

class VulnType(str, Enum):
    XSS = "xss"
    SQLI = "sqli"
    SSRF = "ssrf"
    IDOR = "idor"
    AUTH_BYPASS = "auth_bypass"
    OPEN_REDIRECT = "open_redirect"
    RCE = "rce"
    INFO_DISCLOSURE = "info_disclosure"


class AgentStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    RECON = "recon"
    ATTACKING = "attacking"
    VERIFYING = "verifying"
    DIGGING = "digging"
    COMPLETED = "completed"
    CRASHED = "crashed"
    KILLED = "killed"


class MessageType(str, Enum):
    """Inter-agent message types on the shared bus."""
    STATUS_UPDATE = "status_update"
    FINDING = "finding"
    CANDIDATE_SHARE = "candidate_share"      # share discovered endpoints
    DEDUP_CHECK = "dedup_check"              # ask if someone already tested X
    HEARTBEAT = "heartbeat"
    AGENT_CRASH = "agent_crash"
    AGENT_COMPLETE = "agent_complete"
    SHUTDOWN = "shutdown"


@dataclass
class Finding:
    vuln_type: str
    target: str
    endpoint: str
    description: str
    evidence: str
    severity: str  # info/low/medium/high/critical
    agent_id: str
    depth_reached: int
    confidence: float = 0.0   # 0.0 - 1.0
    raw_request: str = ""
    raw_response: str = ""
    remediation: str = ""
    cwe_id: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self):
        return asdict(self)


@dataclass
class BusMessage:
    """Message passed between agents and orchestrator via the shared queue."""
    msg_type: MessageType
    sender_id: str
    payload: dict
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# --------------------------------------------------------------------------
# Scope & Authorization
# --------------------------------------------------------------------------

@dataclass
class Scope:
    """Defines what the agents are authorized to test."""
    target: str
    authorized: bool = False
    program: str = ""
    excluded_paths: list = field(default_factory=list)
    rate_limit_rps: float = 10.0   # requests per second
    max_depth: int = 7

    def validate(self):
        if not self.authorized:
            raise RuntimeError(
                "SAFETY: You must confirm authorization with --confirm-authorized. "
                "Only test targets you have EXPLICIT WRITTEN PERMISSION to test."
            )
        if not self.target.startswith(("http://", "https://")):
            raise ValueError(f"Target must be a valid URL, got: {self.target}")


# --------------------------------------------------------------------------
# Base Agent (runs as subprocess)
# --------------------------------------------------------------------------

class BaseVulnAgent(ABC):
    """
    One agent = one vulnerability class, running in its own process.

    Workflow per process:
      1. recon()            — gather candidate endpoints/params for this vuln class
      2. attempt(depth)      — try detection technique at current depth
      3. verify(candidate)   — confirm a candidate is a REAL, valid finding
      4. dig_deeper()        — escalate technique/depth when stalled

    Communication:
      - Sends status updates, findings, and heartbeats via message_queue
      - Receives shutdown signals via shutdown_event
    """

    vuln_type: VulnType = None
    max_depth: int = 7
    stall_retries: int = 4
    heartbeat_interval: float = 5.0  # seconds between heartbeats

    def __init__(self, scope: Scope, message_queue: Queue, shutdown_event: Event,
                 shared_state: dict, workspace: Path):
        self.scope = scope
        self.agent_id = f"{self.vuln_type.value}-{uuid.uuid4().hex[:6]}"
        self.message_queue = message_queue
        self.shutdown_event = shutdown_event
        self.shared_state = shared_state
        self.workspace = workspace
        self.depth = 0
        self.stalled_count = 0
        self.findings: list[Finding] = []
        self.last_heartbeat = 0.0
        self.logger = None  # initialized in run() after fork

    # ---- Communication helpers ----

    def _send(self, msg_type: MessageType, payload: dict):
        """Send a message on the shared bus."""
        msg = BusMessage(
            msg_type=msg_type,
            sender_id=self.agent_id,
            payload=payload,
        )
        try:
            self.message_queue.put_nowait(asdict(msg))
        except Exception:
            pass  # don't crash on queue full

    def _heartbeat(self):
        """Send periodic heartbeat so orchestrator knows we're alive."""
        now = time.monotonic()
        if now - self.last_heartbeat >= self.heartbeat_interval:
            self._send(MessageType.HEARTBEAT, {"pid": os.getpid()})
            self.last_heartbeat = now

    def _update_status(self, status: AgentStatus, detail: str = ""):
        """Report status change to orchestrator."""
        self._send(MessageType.STATUS_UPDATE, {
            "status": status.value,
            "detail": detail,
            "depth": self.depth,
            "findings_count": len(self.findings),
            "pid": os.getpid(),
        })

    def _share_candidates(self, candidates: list):
        """Share discovered endpoints with other agents via bus."""
        self._send(MessageType.CANDIDATE_SHARE, {
            "vuln_type": self.vuln_type.value,
            "candidates": candidates[:50],  # cap to avoid huge messages
        })

    def _report_finding(self, finding: Finding):
        """Report a verified finding to orchestrator."""
        self.findings.append(finding)
        self._send(MessageType.FINDING, finding.to_dict())

    # ---- Abstract methods for subclasses to implement ----

    @abstractmethod
    def recon(self) -> list:
        """Return a list of candidate endpoints/params to test."""
        raise NotImplementedError

    @abstractmethod
    def attempt(self, candidates: list, depth: int) -> Optional[dict]:
        """
        Try to find a vuln at the given depth/escalation level.
        Return a raw 'hit' dict if something promising is found, else None.
        """
        raise NotImplementedError

    @abstractmethod
    def verify(self, hit: dict) -> Optional[Finding]:
        """
        Independently verify a hit is a real, reproducible vulnerability.
        Return a Finding if confirmed, else None.
        """
        raise NotImplementedError

    def dig_deeper(self, depth: int) -> int:
        """
        Called when attempt() has stalled. Override to escalate technique.
        Default: increment depth.
        """
        self.logger.info(f"Digging deeper -> depth {depth + 1}")
        return depth + 1

    # ---- Main execution loop (runs in subprocess) ----

    def run(self) -> list[Finding]:
        """Main agent loop. Called inside the subprocess."""
        # Setup logging inside subprocess (can't share loggers across fork)
        log_dir = self.workspace / "logs"
        self.logger = _setup_logging(self.agent_id, log_dir)

        self.logger.info(
            f"Agent {self.agent_id} started (PID {os.getpid()}) "
            f"targeting {self.scope.target}"
        )
        self._update_status(AgentStatus.RUNNING, "initializing")

        try:
            # Phase 1: Recon
            self._update_status(AgentStatus.RECON, "gathering candidates")
            candidates = self.recon()

            if not candidates:
                self.logger.warning("Recon returned no candidates. Stopping.")
                self._update_status(AgentStatus.COMPLETED, "no candidates found")
                self._send(MessageType.AGENT_COMPLETE, {
                    "findings": [f.to_dict() for f in self.findings]
                })
                return self.findings

            # Share candidates with other agents
            self._share_candidates(candidates)

            # Phase 2: Attack loop with depth escalation
            depth = 0
            max_depth = self.scope.max_depth or self.max_depth

            while depth < max_depth and not self.shutdown_event.is_set():
                self._heartbeat()
                self._update_status(AgentStatus.ATTACKING, f"depth={depth}")

                stall = 0
                while stall < self.stall_retries and not self.shutdown_event.is_set():
                    self._heartbeat()

                    hit = self.attempt(candidates, depth)
                    if hit:
                        self._update_status(AgentStatus.VERIFYING, f"verifying hit at depth={depth}")
                        finding = self.verify(hit)
                        if finding:
                            finding.depth_reached = depth
                            self.logger.info(
                                f"✓ VALID FINDING at depth {depth}: {finding.description}"
                            )
                            self._report_finding(finding)
                            # Don't stop — keep hunting for more!
                        else:
                            self.logger.debug("Hit did not verify (false positive). Continuing.")

                    stall += 1
                    # Rate limiting
                    time.sleep(1.0 / max(self.scope.rate_limit_rps, 0.1))

                # Escalate depth
                self._update_status(AgentStatus.DIGGING, f"escalating from depth={depth}")
                depth = self.dig_deeper(depth)
                self.stalled_count += 1

            self.logger.info(
                f"Agent complete. max_depth={max_depth} reached. "
                f"{len(self.findings)} finding(s)."
            )

        except Exception as e:
            self.logger.error(f"Agent crashed: {e}\n{traceback.format_exc()}")
            self._send(MessageType.AGENT_CRASH, {
                "error": str(e),
                "traceback": traceback.format_exc(),
            })
            self._update_status(AgentStatus.CRASHED, str(e))
            return self.findings

        self._update_status(AgentStatus.COMPLETED, f"{len(self.findings)} findings")
        self._send(MessageType.AGENT_COMPLETE, {
            "findings": [f.to_dict() for f in self.findings],
        })
        return self.findings


# --------------------------------------------------------------------------
# Agent Implementations (stubs — plug in your tools here)
# --------------------------------------------------------------------------

class XSSAgent(BaseVulnAgent):
    vuln_type = VulnType.XSS

    def recon(self) -> list:
        self.logger.info("Recon: crawling for reflected/stored XSS surfaces")
        # TODO: Use httpx/katana to crawl, extract params that reflect input
        # Example: subprocess.run(["katana", "-u", self.scope.target, "-jc"])
        return []

    def attempt(self, candidates: list, depth: int) -> Optional[dict]:
        # TODO: Send XSS payloads, escalate complexity with depth
        # depth 0: basic <script>alert(1)</script>
        # depth 1: event handlers, svg/onload
        # depth 2: encoding bypass, polyglots
        # depth 3+: DOM-based, mutation XSS
        return None

    def verify(self, hit: dict) -> Optional[Finding]:
        # TODO: Headless browser verification, check if payload executes
        return None


class SQLiAgent(BaseVulnAgent):
    vuln_type = VulnType.SQLI

    def recon(self) -> list:
        self.logger.info("Recon: identifying SQL injection candidates")
        # TODO: Find params that interact with database (numeric IDs, search, etc.)
        return []

    def attempt(self, candidates: list, depth: int) -> Optional[dict]:
        # depth 0: error-based ('", boolean-based)
        # depth 1: time-based blind
        # depth 2: UNION-based
        # depth 3+: second-order, out-of-band
        return None

    def verify(self, hit: dict) -> Optional[Finding]:
        # TODO: Confirm with time delay differential or data extraction
        return None


class SSRFAgent(BaseVulnAgent):
    vuln_type = VulnType.SSRF

    def recon(self) -> list:
        self.logger.info("Recon: finding SSRF-prone params (URL fetchers, webhooks)")
        # TODO: Look for URL params, webhook configs, import/export features
        return []

    def attempt(self, candidates: list, depth: int) -> Optional[dict]:
        # depth 0: direct URL fetch to canary
        # depth 1: redirect chains
        # depth 2: DNS rebinding
        # depth 3+: cloud metadata endpoints
        return None

    def verify(self, hit: dict) -> Optional[Finding]:
        # TODO: Check canary server for callback
        return None


class IDORAgent(BaseVulnAgent):
    vuln_type = VulnType.IDOR

    def recon(self) -> list:
        self.logger.info("Recon: finding object-reference endpoints")
        # TODO: Identify endpoints with numeric/UUID IDs in path/params
        return []

    def attempt(self, candidates: list, depth: int) -> Optional[dict]:
        # depth 0: increment/decrement IDs
        # depth 1: try other users' IDs
        # depth 2: parameter pollution, HPP
        # depth 3+: GraphQL introspection, batch queries
        return None

    def verify(self, hit: dict) -> Optional[Finding]:
        # TODO: Confirm access to unauthorized resource
        return None


class AuthBypassAgent(BaseVulnAgent):
    vuln_type = VulnType.AUTH_BYPASS

    def recon(self) -> list:
        self.logger.info("Recon: mapping auth-gated endpoints")
        # TODO: Crawl with and without auth, diff the responses
        return []

    def attempt(self, candidates: list, depth: int) -> Optional[dict]:
        # depth 0: remove auth headers
        # depth 1: HTTP method switching (GET->POST etc.)
        # depth 2: path traversal past auth (/admin/../admin)
        # depth 3+: JWT manipulation, role confusion
        return None

    def verify(self, hit: dict) -> Optional[Finding]:
        # TODO: Confirm unauthorized access
        return None


class OpenRedirectAgent(BaseVulnAgent):
    vuln_type = VulnType.OPEN_REDIRECT

    def recon(self) -> list:
        self.logger.info("Recon: finding redirect parameters")
        # TODO: Look for ?url=, ?next=, ?redirect=, ?return_to= etc.
        return []

    def attempt(self, candidates: list, depth: int) -> Optional[dict]:
        # depth 0: direct external URL
        # depth 1: protocol-relative //evil.com
        # depth 2: URL-encoded, double-encoded
        # depth 3+: data: and javascript: URIs
        return None

    def verify(self, hit: dict) -> Optional[Finding]:
        return None


class RCEAgent(BaseVulnAgent):
    vuln_type = VulnType.RCE

    def recon(self) -> list:
        self.logger.info("Recon: finding potential command injection surfaces")
        # TODO: File upload, template injection, deserialization endpoints
        return []

    def attempt(self, candidates: list, depth: int) -> Optional[dict]:
        # depth 0: basic command injection (;, |, &&)
        # depth 1: template injection ({{7*7}})
        # depth 2: deserialization gadgets
        # depth 3+: file upload chains, polyglot files
        return None

    def verify(self, hit: dict) -> Optional[Finding]:
        return None


class InfoDisclosureAgent(BaseVulnAgent):
    vuln_type = VulnType.INFO_DISCLOSURE

    def recon(self) -> list:
        self.logger.info("Recon: checking for info disclosure endpoints")
        # TODO: /.git, /.env, /robots.txt, /sitemap.xml, stack traces,
        #       verbose error pages, debug endpoints
        return []

    def attempt(self, candidates: list, depth: int) -> Optional[dict]:
        # depth 0: common paths (.git/config, .env, etc.)
        # depth 1: backup files (.bak, .old, ~)
        # depth 2: debug/admin endpoints
        # depth 3+: header analysis, version fingerprinting
        return None

    def verify(self, hit: dict) -> Optional[Finding]:
        return None


# --------------------------------------------------------------------------
# Agent Registry
# --------------------------------------------------------------------------

AGENT_REGISTRY = {
    VulnType.XSS: XSSAgent,
    VulnType.SQLI: SQLiAgent,
    VulnType.SSRF: SSRFAgent,
    VulnType.IDOR: IDORAgent,
    VulnType.AUTH_BYPASS: AuthBypassAgent,
    VulnType.OPEN_REDIRECT: OpenRedirectAgent,
    VulnType.RCE: RCEAgent,
    VulnType.INFO_DISCLOSURE: InfoDisclosureAgent,
}


# --------------------------------------------------------------------------
# Agent Process Wrapper
# --------------------------------------------------------------------------

def _agent_worker(agent_cls, scope: Scope, message_queue: Queue,
                  shutdown_event: Event, shared_state: dict,
                  workspace: Path):
    """
    Top-level function that runs inside each subprocess.
    Creates the agent instance and executes its run() loop.
    """
    if sys.platform == "win32":
        try:
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            if hasattr(sys.stderr, "reconfigure"):
                sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    # Ignore SIGINT in workers — let orchestrator handle it
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    agent = agent_cls(
        scope=scope,
        message_queue=message_queue,
        shutdown_event=shutdown_event,
        shared_state=shared_state,
        workspace=workspace,
    )

    try:
        findings = agent.run()
        return findings
    except Exception as e:
        # Last-resort crash handler
        try:
            message_queue.put_nowait(asdict(BusMessage(
                msg_type=MessageType.AGENT_CRASH,
                sender_id=agent.agent_id,
                payload={"error": str(e), "traceback": traceback.format_exc()},
            )))
        except Exception:
            pass


# --------------------------------------------------------------------------
# Orchestrator (Daemon)
# --------------------------------------------------------------------------

class Orchestrator:
    """
    The main orchestrator daemon, inspired by AO's architecture.

    Responsibilities:
      • Spawn one subprocess per vulnerability agent
      • Monitor health via heartbeats, restart crashed agents
      • Collect and deduplicate findings from the message bus
      • Print a live status dashboard to the terminal
      • Save a structured JSON report on completion
    """

    def __init__(self, scope: Scope, vuln_types: list[VulnType],
                 max_workers: int = 3, max_restarts: int = 2):
        self.scope = scope
        self.vuln_types = vuln_types
        self.max_workers = max_workers
        self.max_restarts = max_restarts

        self.findings: list[Finding] = []
        self.finding_hashes: set = set()  # deduplication

        # Multiprocessing primitives
        self.message_queue = Queue()
        self.shutdown_event = Event()
        self.manager = Manager()
        self.shared_state = self.manager.dict()

        # Agent tracking
        self.agents: dict[str, dict] = {}  # agent_id -> metadata
        self.processes: dict[str, Process] = {}
        self.restart_counts: dict[str, int] = {}  # vuln_type -> restart count
        self.pending_vuln_types: list[VulnType] = list(self.vuln_types)

        self.logger = _setup_logging("orchestrator", RESULTS_DIR / "logs")
        self.start_time = None

    def _create_workspace(self, vuln_type: VulnType) -> Path:
        """Create isolated workspace directory for an agent."""
        ws = WORKSPACE_DIR / f"{vuln_type.value}_{uuid.uuid4().hex[:6]}"
        ws.mkdir(parents=True, exist_ok=True)
        (ws / "logs").mkdir(exist_ok=True)
        (ws / "evidence").mkdir(exist_ok=True)
        return ws

    def _spawn_agent(self, vuln_type: VulnType) -> Optional[str]:
        """Spawn a single agent as a subprocess."""
        agent_cls = AGENT_REGISTRY.get(vuln_type)
        if not agent_cls:
            self.logger.warning(f"No agent implemented for {vuln_type}, skipping.")
            return None

        workspace = self._create_workspace(vuln_type)

        proc = Process(
            target=_agent_worker,
            args=(agent_cls, self.scope, self.message_queue,
                  self.shutdown_event, self.shared_state, workspace),
            daemon=True,
        )
        proc.start()

        agent_id = f"{vuln_type.value}-{proc.pid}"
        self.agents[agent_id] = {
            "vuln_type": vuln_type,
            "pid": proc.pid,
            "status": AgentStatus.PENDING,
            "workspace": str(workspace),
            "started_at": datetime.now(timezone.utc).isoformat(),
            "last_heartbeat": time.monotonic(),
            "findings_count": 0,
        }
        self.processes[agent_id] = proc
        self.restart_counts.setdefault(vuln_type.value, 0)

        self.logger.info(
            f"  ▸ Spawned {vuln_type.value} agent (PID {proc.pid}) "
            f"in {workspace}"
        )
        return agent_id

    def _process_messages(self, timeout: float = 0.1):
        """Drain the message queue and process all pending messages."""
        while True:
            try:
                raw = self.message_queue.get(timeout=timeout)
                timeout = 0  # subsequent reads are non-blocking
            except queue.Empty:
                break

            msg_type = raw.get("msg_type", "")
            sender = raw.get("sender_id", "unknown")
            payload = raw.get("payload", {})

            if msg_type == MessageType.STATUS_UPDATE:
                status = payload.get("status", "unknown")
                detail = payload.get("detail", "")
                # Update agent tracking
                for aid, info in self.agents.items():
                    if info.get("pid") == payload.get("pid"):
                        info["status"] = status
                        info["findings_count"] = payload.get("findings_count", 0)
                        break

            elif msg_type == MessageType.FINDING:
                finding = Finding(**{k: v for k, v in payload.items()
                                    if k in Finding.__dataclass_fields__})
                # Dedup by (vuln_type, endpoint, description)
                fhash = hash((finding.vuln_type, finding.endpoint,
                              finding.description))
                if fhash not in self.finding_hashes:
                    self.finding_hashes.add(fhash)
                    self.findings.append(finding)
                    self.logger.info(
                        f"  ★ NEW FINDING [{finding.severity}] "
                        f"{finding.vuln_type} @ {finding.endpoint}: "
                        f"{finding.description}"
                    )

            elif msg_type == MessageType.CANDIDATE_SHARE:
                # Store in shared state so other agents can access
                vt = payload.get("vuln_type", "unknown")
                candidates = payload.get("candidates", [])
                existing = self.shared_state.get("candidates", {})
                existing[vt] = candidates
                self.shared_state["candidates"] = existing

            elif msg_type == MessageType.HEARTBEAT:
                for aid, info in self.agents.items():
                    if info.get("pid") == payload.get("pid"):
                        info["last_heartbeat"] = time.monotonic()
                        break

            elif msg_type == MessageType.AGENT_CRASH:
                error = payload.get("error", "unknown")
                self.logger.error(f"Agent {sender} crashed: {error}")

            elif msg_type == MessageType.AGENT_COMPLETE:
                self.logger.info(f"Agent {sender} completed.")

    def _active_count(self) -> int:
        """Count how many agent processes are currently alive."""
        return sum(1 for p in self.processes.values() if p.is_alive())

    def _spawn_next_agents(self):
        """Spawn queued agents up to the max_workers limit."""
        while self.pending_vuln_types and self._active_count() < self.max_workers:
            if self.shutdown_event.is_set():
                break
            vt = self.pending_vuln_types.pop(0)
            self._spawn_agent(vt)

    def _check_health(self):
        """Check for dead processes, handle restarts, and fill available worker slots."""
        for agent_id, proc in list(self.processes.items()):
            if not proc.is_alive():
                info = self.agents.get(agent_id, {})
                vuln_type = info.get("vuln_type")
                status = info.get("status", "unknown")

                if status not in (AgentStatus.COMPLETED, AgentStatus.KILLED):
                    # Agent died unexpectedly
                    info["status"] = AgentStatus.CRASHED
                    restarts = self.restart_counts.get(vuln_type.value, 0)

                    if restarts < self.max_restarts:
                        self.logger.warning(
                            f"Agent {agent_id} died (exit={proc.exitcode}). "
                            f"Queuing restart ({restarts + 1}/{self.max_restarts})..."
                        )
                        self.restart_counts[vuln_type.value] = restarts + 1
                        self.pending_vuln_types.append(vuln_type)
                    else:
                        self.logger.error(
                            f"Agent {agent_id} exceeded max restarts. Giving up."
                        )

        # Spawn queued agents if slots are available
        self._spawn_next_agents()

    def _all_done(self) -> bool:
        """Check if all queued and active agent processes have finished."""
        return len(self.pending_vuln_types) == 0 and all(not p.is_alive() for p in self.processes.values())

    def _print_status(self):
        """Print a live status dashboard to terminal."""
        elapsed = time.monotonic() - self.start_time if self.start_time else 0.0
        active_count = self._active_count()
        lines = [
            "",
            f"{'═' * 70}",
            f"  HUNTERV2 ORCHESTRATOR — {self.scope.target}",
            f"  Elapsed: {elapsed:.0f}s | Active: {active_count}/{self.max_workers} | "
            f"Queued: {len(self.pending_vuln_types)} | Findings: {len(self.findings)}",
            f"{'─' * 70}",
        ]
        for agent_id, info in self.agents.items():
            status = info.get("status", "?")
            vt = info.get("vuln_type", "?")
            pid = info.get("pid", "?")
            fc = info.get("findings_count", 0)

            # Status emoji
            emoji = {
                AgentStatus.PENDING: "⏳",
                AgentStatus.RUNNING: "🔄",
                AgentStatus.RECON: "🔍",
                AgentStatus.ATTACKING: "⚔️",
                AgentStatus.VERIFYING: "✅",
                AgentStatus.DIGGING: "⛏️",
                AgentStatus.COMPLETED: "✔️",
                AgentStatus.CRASHED: "💥",
                AgentStatus.KILLED: "🛑",
            }.get(status, "❓")

            vt_display = vt.value if hasattr(vt, 'value') else str(vt)
            status_display = status.value if hasattr(status, 'value') else str(status)
            lines.append(
                f"  {emoji} {vt_display:<18} PID:{pid:<7} "
                f"Status:{status_display:<12} Findings:{fc}"
            )

        if self.findings:
            lines.append(f"{'─' * 70}")
            lines.append("  Latest findings:")
            for f in self.findings[-5:]:  # show last 5
                lines.append(
                    f"    [{f.severity}] {f.vuln_type} @ {f.endpoint}: "
                    f"{f.description[:60]}"
                )

        lines.append(f"{'═' * 70}")
        try:
            print("\n".join(lines), flush=True)
        except UnicodeEncodeError:
            safe_lines = [line.encode("ascii", errors="replace").decode("ascii") for line in lines]
            print("\n".join(safe_lines), flush=True)

    def _save_report(self):
        """Save comprehensive JSON report."""
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)

        safe_target = (self.scope.target
                       .replace("://", "_")
                       .replace("/", "_")
                       .replace(":", "_"))
        report_path = RESULTS_DIR / f"report_{safe_target}_{int(time.time())}.json"

        report = {
            "meta": {
                "target": self.scope.target,
                "program": self.scope.program,
                "scan_time": datetime.now(timezone.utc).isoformat(),
                "duration_seconds": time.monotonic() - self.start_time,
                "agents_spawned": len(self.agents),
                "total_findings": len(self.findings),
            },
            "agents": {
                aid: {
                    "vuln_type": (info["vuln_type"].value
                                  if hasattr(info["vuln_type"], "value")
                                  else str(info["vuln_type"])),
                    "status": (info["status"].value
                               if hasattr(info["status"], "value")
                               else str(info["status"])),
                    "workspace": info["workspace"],
                    "findings_count": info["findings_count"],
                }
                for aid, info in self.agents.items()
            },
            "findings": [f.to_dict() for f in self.findings],
        }

        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)

        self.logger.info(
            f"Report saved to {report_path} "
            f"({len(self.findings)} findings)"
        )
        return report_path

    def run(self):
        """
        Main orchestrator loop.

        1. Validate scope & authorization
        2. Spawn agent subprocesses
        3. Monitor message bus, update status, check health
        4. Wait for all agents to complete (or handle shutdown)
        5. Aggregate and save report
        """
        self.start_time = time.monotonic()
        self.scope.validate()

        # Setup directories
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)

        self.logger.info(
            f"\n{'═' * 70}\n"
            f"  HUNTERV2 — Multi-Agent Vulnerability Orchestrator\n"
            f"  Target: {self.scope.target}\n"
            f"  Agents: {', '.join(vt.value for vt in self.vuln_types)}\n"
            f"  Workers: {self.max_workers} | Max Depth: {self.scope.max_depth}\n"
            f"{'═' * 70}"
        )

        # Install SIGINT handler for graceful shutdown
        original_sigint = signal.getsignal(signal.SIGINT)

        def _graceful_shutdown(signum, frame):
            self.logger.info("\n⚠️  Ctrl+C received. Shutting down agents gracefully...")
            self.shutdown_event.set()

        signal.signal(signal.SIGINT, _graceful_shutdown)

        try:
            # Phase 1: Spawn initial batch of agents (up to max_workers)
            self.logger.info(
                f"Starting hunt with {len(self.vuln_types)} agent types configured "
                f"(max {self.max_workers} running concurrently)..."
            )
            self._spawn_next_agents()

            # Phase 2: Monitor loop
            status_interval = 3.0  # print status every N seconds
            health_interval = 10.0  # check health every N seconds
            last_status = 0.0
            last_health = 0.0

            while not self._all_done() and not self.shutdown_event.is_set():
                # Process messages from agents
                self._process_messages(timeout=0.5)

                # Replenish agent slots if any finished or died
                self._spawn_next_agents()

                now = time.monotonic()

                # Periodic status display
                if now - last_status >= status_interval:
                    self._print_status()
                    last_status = now

                # Periodic health check
                if now - last_health >= health_interval:
                    self._check_health()
                    last_health = now

            # Drain remaining messages
            self._process_messages(timeout=1.0)

        finally:
            # Phase 3: Cleanup
            signal.signal(signal.SIGINT, original_sigint)

            # Kill any still-running processes
            for agent_id, proc in self.processes.items():
                if proc.is_alive():
                    self.logger.info(f"Terminating agent {agent_id}...")
                    proc.terminate()
                    proc.join(timeout=5)
                    if proc.is_alive():
                        proc.kill()

            # Final status
            self._print_status()

            # Save report
            report_path = self._save_report()

            # Cleanup manager
            try:
                self.manager.shutdown()
            except Exception:
                pass

        return self.findings


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="HunterV2 — Multi-Agent Vulnerability Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target https://example.com --confirm-authorized
  %(prog)s --target https://example.com --confirm-authorized --vulns xss sqli ssrf
  %(prog)s --target https://example.com --confirm-authorized --workers 8 --max-depth 10
        """,
    )
    parser.add_argument(
        "--target", required=True,
        help="Target base URL, e.g. https://example.com",
    )
    parser.add_argument(
        "--confirm-authorized", action="store_true",
        help="You MUST pass this to confirm you have written authorization "
             "to test this target",
    )
    parser.add_argument(
        "--program", default="",
        help="Bug bounty program name, if applicable",
    )
    parser.add_argument(
        "--vulns", nargs="+",
        default=[v.value for v in VulnType],
        choices=[v.value for v in VulnType],
        help="Which vulnerability classes to hunt for",
    )
    parser.add_argument(
        "--workers", type=int, default=3,
        help="Max agents that run at the same time (concurrency limit)",
    )
    parser.add_argument("--max-depth", type=int, default=7)
    parser.add_argument(
        "--rate-limit", type=float, default=10.0,
        help="Max requests per second per agent",
    )
    parser.add_argument(
        "--max-restarts", type=int, default=2,
        help="Max times to restart a crashed agent",
    )

    args = parser.parse_args()

    scope = Scope(
        target=args.target,
        authorized=args.confirm_authorized,
        program=args.program,
        rate_limit_rps=args.rate_limit,
        max_depth=args.max_depth,
    )

    vuln_types = [VulnType(v) for v in args.vulns]

    orchestrator = Orchestrator(
        scope=scope,
        vuln_types=vuln_types,
        max_workers=args.workers,
        max_restarts=args.max_restarts,
    )

    findings = orchestrator.run()

    print(f"\n{'=' * 60}")
    print(f"Done. {len(findings)} valid finding(s).")
    for f in findings:
        print(f"  - [{f.severity}] {f.vuln_type} @ {f.endpoint}: {f.description}")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    # Required for Windows multiprocessing
    multiprocessing.freeze_support()
    main()
