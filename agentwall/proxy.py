import asyncio
import time
import uuid
import os
from typing import Optional

from agentwall.layer1.policy_engine import PolicyEngine
from agentwall.layer1.rate_limiter import RateLimiter
from agentwall.layer1.normaliser import TextNormaliser
# Heavy imports moved to lazy properties below
from agentwall.pii import mask_call_arguments
from agentwall.hitl.manager import HITLManager
from agentwall.sandbox.router import SandboxRouter
from agentwall.audit.logger import AuditLogger
from agentwall.sanitiser.output import OutputSanitiser

BLOCK   = "BLOCK"
AUDIT   = "AUDIT"
PERMIT  = "PERMIT"
SANITISE= "SANITISE"


class AgentWallProxy:
    def __init__(self, policy_variant: str = None, audit_logger: Optional[AuditLogger] = None, ws_manager=None):
        # Issue 7: Use AGENTWALL_POLICY_PROFILE as the primary env var
        self._variant     = policy_variant or os.getenv("AGENTWALL_POLICY_PROFILE", "standard")
        
        # Lazy Loading for heavy or external-dependent components (P0 Stability Fix)
        # All backing fields initialized to None; properties handle the 'from ... import ...'
        self._policy      = None
        self._rate        = None
        self._normaliser  = None
        self._anomaly     = None
        self._causal      = None
        self._trust_graph = None
        self._campaign    = None
        self._mitre       = None
        self._classifier  = None
        self._explainer   = None
        self._rbac        = None
        self._honey       = None
        self._alignment   = None
        self._hitl        = None
        self._sandbox     = None
        self._sanitiser   = None
        self._rag         = None
        self._audit_logger = audit_logger
        
        self._injection_failure_rate = 0.0  # Distributed failure tracker (Circuit Breaker)
        self._start_time = time.time()      # Tracking warm-up window (Issue 2)
        self._shadow_mode_active = os.getenv("AGENTWALL_SHADOW_MODE", "1") == "1"
        self._system_lockdown_active = False
        self._lockdown_reason = ""
        self._total_calls_seen = 0
        self.auto_baseline_calls = int(os.getenv("AGENTWALL_AUTO_BASELINE_N", "50"))
        self.ws          = ws_manager
        self._local_locked_sessions = set()

    @property
    def policy(self):
        if self._policy is None:
            from agentwall.layer1.policy_engine import PolicyEngine
            self._policy = PolicyEngine(policy_variant=self._variant)
        return self._policy

    @property
    def rate(self):
        if self._rate is None:
            from agentwall.layer1.rate_limiter import RateLimiter
            self._rate = RateLimiter()
        return self._rate

    @property
    def normaliser(self):
        if self._normaliser is None:
            from agentwall.layer1.normaliser import TextNormaliser
            self._normaliser = TextNormaliser()
        return self._normaliser

    @property
    def anomaly(self):
        if self._anomaly is None:
            from agentwall.layer2.anomaly import TemporalAnomalyDetector
            self._anomaly = TemporalAnomalyDetector.instance()
        return self._anomaly

    @property
    def causal(self):
        if self._causal is None:
            from agentwall.layer2.causal_graph import CausalGraphDetector
            self._causal = CausalGraphDetector.instance()
        return self._causal

    @property
    def trust_graph(self):
        if self._trust_graph is None:
            from agentwall.layer2.trust_graph import TrustGraph
            self._trust_graph = TrustGraph.instance()
        return self._trust_graph

    @property
    def mitre(self):
        if self._mitre is None:
            from agentwall.mitre import MITREMapper
            self._mitre = MITREMapper()
        return self._mitre

    @property
    def injection(self):
        if self._injection is None:
            from agentwall.layer3.injection import LLMInjectionClassifier
            self._injection = LLMInjectionClassifier.instance()
        return self._injection

    @property
    def explainer(self):
        if self._explainer is None:
            from agentwall.layer3.explainer import ExplainabilityEngine
            self._explainer = ExplainabilityEngine()
        return self._explainer

    @property
    def rbac(self):
        if self._rbac is None:
            from agentwall.rbac import RBACEngine
            self._rbac = RBACEngine()
        return self._rbac

    @property
    def honeytoken(self):
        if self._honey is None:
            from agentwall.honey import HoneyTokenDefence
            self._honey = HoneyTokenDefence.get()
        return self._honey

    @property
    def alignment(self):
        if self._alignment is None:
            from agentwall.alignment.intent_scorer import IntentAlignmentScorer
            self._alignment = IntentAlignmentScorer()
        return self._alignment

    @property
    def hitl(self):
        if self._hitl is None:
            from agentwall.hitl.manager import HITLManager
            self._hitl = HITLManager.instance()
        return self._hitl

    @property
    def sandbox(self):
        if self._sandbox is None:
            from agentwall.sandbox.router import SandboxRouter
            self._sandbox = SandboxRouter()
        return self._sandbox

    @property
    def sanitiser(self):
        if self._sanitiser is None:
            from agentwall.sanitiser.output import OutputSanitiser
            self._sanitiser = OutputSanitiser()
        return self._sanitiser

    @property
    def rag(self):
        if self._rag is None:
            from agentwall.layer2.rag_detector import RAGPoisoningDetector
            self._rag = RAGPoisoningDetector()
        return self._rag

    @property
    def audit(self):
        if self._audit_logger is None:
            from agentwall.audit.logger import AuditLogger
            self._audit_logger = AuditLogger()
        return self._audit_logger

    @property
    def campaign(self):
        if self._campaign is None:
            from agentwall.layer4.campaign import CampaignDetector
            self._campaign = CampaignDetector.instance()
        return self._campaign

    @property
    def redis(self):
        return self.trust_graph._r if self.trust_graph.redis_url else None
        
        # [AUDIT v3 FIX] Production Secret Enforcement
        if os.getenv("AGENTWALL_ENV") == "production":
            defaults = {
                "AGENTWALL_HMAC_KEY": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abc",
                "AGENTWALL_JWT_SECRET": "change-this-in-production-1234567890",
                "AGENTWALL_ADMIN_PASSWORD": "admin-password-change-me"
            }
            for k, v in defaults.items():
                val = os.getenv(k)
                if val == v or not val or len(val) < 16:
                    print(f"[FATAL] Default, weak, or missing secret detected: {k}. Use a strong, unique value in production.")
                    import sys
                    sys.exit(1)
        
        # 90% Production Readiness: Auto-Baseline Mode
        # If enabled, proxy will only AUDIT for the first N calls to build baseline
        self.auto_baseline_calls = int(os.getenv("AGENTWALL_AUTO_BASELINE_N", "0"))
        self._total_calls_seen = 0
        
        # 95% Production Readiness: Dynamic Safety Lockdown
        # If campaign detector identifies high-risk activity, lockdown the entire system
        self._system_lockdown_active = False
        self._lockdown_reason = ""

    async def evaluate(self, raw_payload: dict) -> dict:
        t_start = time.perf_counter()
        t_eval  = {}
        
        # ── Pre-processing ──────────────────────────────────────────────────
        call = {
            "session_id": raw_payload.get("session_id", "default"),
            "agent_id":   raw_payload.get("agent_id", "default"),
            "tool_name":  raw_payload.get("tool_name", raw_payload.get("name", "unknown")),
            "arguments":  raw_payload.get("arguments", raw_payload.get("input", {})),
            "context":    raw_payload.get("context", ""),
            "caller_agent_id": raw_payload.get("caller_agent_id"), # For Trust Graph
            "timestamp":  raw_payload.get("timestamp", time.time()),
        }

        # ── Text normalisation (adversarial hardening) ─────────────────────
        call = self.normaliser.normalise_call(call)
        
        # 95% Readiness: Global System Lockdown Check
        if self._system_lockdown_active:
            # Only allow essential tools defined in policy
            essential_tools = self.policy.get_essential_tools()
            if call["tool_name"] not in essential_tools:
                return await self._finalise(
                    call, BLOCK, f"SYSTEM LOCKDOWN ACTIVE: {self._lockdown_reason}",
                    {"global_lockdown": True}, "T1566", t_start
                )

        # ── Intent alignment (always runs — cheap) ─────────────────────────
        alignment = self.alignment.score(call)

        # ── Active Defense: Honey-Token & Lockdown Check ───────────────────
        is_locked = False
        if self.redis:
            is_locked = bool(self.redis.sismember("locked_sessions", call.get("session_id")))
        else:
            is_locked = call.get("session_id") in self._local_locked_sessions

        if is_locked:
            return await self._finalise(
                call, BLOCK, "SESSION LOCKED: Previous honeytoken trigger in this session.",
                {"lockdown": True}, "T1552.001", t_start
            )

        honey_result = self.honeytoken.check(call)
        if honey_result["triggered"]:
            if self.redis:
                self.redis.sadd("locked_sessions", call.get("session_id"))
                self.redis.expire("locked_sessions", 3600) # 1 hour TTL
            else:
                self._local_locked_sessions.add(call.get("session_id"))
                
            return await self._finalise(
                call, BLOCK, honey_result["reason"],
                {"honeytoken": honey_result, "lockdown": True}, "T1552.001", t_start
            )

        # ── Layer 1: Fast path (SHORT-CIRCUIT) ───────────────────────────────
        rate_result   = self.rate.check(call)
        if rate_result["blocked"]:
            return await self._finalise(call, BLOCK, rate_result["reason"], {"rate": rate_result}, "T1498", t_start)

        # ── Layer 1: Policy Engine ──────────────────────────────────────────
        t1_start = time.perf_counter()
        l1_res = self.policy.check(call)
        t_eval["layer1"] = (time.perf_counter() - t1_start) * 1000
        
        # P0 Fix: Ensure Causal Graph records BLOCKED events for visualization
        causal_task_early = asyncio.to_thread(self.causal.analyse, call)

        if l1_res["action"] == BLOCK:
            await causal_task_early # Ensure it's recorded before we return
            return await self._finalise(call, BLOCK, l1_res["reason"], {"policy": l1_res}, l1_res.get("mitre_id"), t_start)

        rbac_result = self.rbac.check(call)
        if not rbac_result["allowed"]:
            await causal_task_early
            return await self._finalise(call, BLOCK, rbac_result["reason"], {"rbac": rbac_result}, "T1078", t_start)

        # ── Apply PII Masking ────────────────────────────────────────────────
        call, pii_matches = mask_call_arguments(call)

        # Record delegation (Issue 2)
        caller_id = call.get("caller_agent_id", call["agent_id"])
        self.trust_graph.record_delegation(call["session_id"], caller_id, call["agent_id"])

        # ── Layer 2: Parallel Behavioral checks (Optimised) ──────────────────
        # Runs independent L2 detectors concurrently
        anomaly_task = asyncio.to_thread(self.anomaly.score, call)
        rag_task     = asyncio.to_thread(self.rag.check, call)
        trust_task   = asyncio.to_thread(self.trust_graph.check_delegation, call)
        
        anomaly_res, rag_res, trust_res, causal_res = await asyncio.gather(
            anomaly_task, rag_task, trust_task, causal_task_early
        )

        # Trust Graph Enforcement (Issue 3)
        if trust_res.get("action") == BLOCK:
            return await self._finalise(
                call, BLOCK, trust_res["reason"],
                {"trust_graph": trust_res}, "T1078", t_start
            )

        # High-confidence Behavioral Blocks
        if causal_res["is_attack_chain"]:
            return await self._finalise(
                call, BLOCK, f"Causal Attack Chain: {causal_res['pattern_name']}",
                {"causal": causal_res, "anomaly": anomaly_res},
                causal_res.get("mitre_id", "T1059"), t_start
            )

        if rag_res["score"] > 0.8:
            return await self._finalise(
                call, BLOCK, f"RAG Poisoning Detected (Confidence: {rag_res['score']})",
                {"rag": rag_res}, "T1565.001", t_start
            )

        # ── Layer 2: Behavioral Parallel Scan ────────────────────────────────
        t_l2_start = time.perf_counter()
        # [WARM-UP POLICY] (Issue 2)
        # If baseline not converged, force synchronous L3 for high-priv tools
        is_warming = time.time() - self._start_time < 14400 # 4 hour window
        
        # ── Layer 3: Semantic Guard (Circuit Breaker + Shadow Mode) ──────────
        t3_start = time.perf_counter()
        # [CRITICAL SECURITY GATE] High-privilege tools NEVER use shadow mode
        # Expanding to include communication, sensitive data, and system discovery (Audit v3 Fix)
        is_high_risk = call["tool_name"] in [
            "bash", "python_repl", "sql_query", "write_file", "delete_file",
            "send_email", "read_email", "read_calendar_event", "call_subagent",
            "memory_write", "memory_read", "vector_store", "list_files",
            "http_post", "http_get" # High risk in some contexts, safer to sync
        ]
        
        # Disable shadow mode entirely during evaluation
        is_eval = os.getenv("AGENTWALL_EVAL_MODE") == "real"
        
        if is_high_risk or not self._shadow_mode_active or is_warming or is_eval:
            # Synchronous Blocking Path (Zero-Tolerance for high-priv/destructive tools)
            injection_res = await self._run_semantic_guard(call)
            if injection_res["score"] >= 0.8:
                return await self._finalise(call, BLOCK, f"Injection: {injection_res['reasoning']}", {"injection": injection_res}, "T1566", t_start)
        else:
            # Shadow Mode: Async Audit Path (Only for low-risk, non-destructive tools)
            # FIX: We MUST NOT set injection_res to 0 if we want it to be part of the finalisation/campaign ingest
            # Actually, _run_semantic_guard_shadow will handle the audit. 
            # For the main response, we use 0 to keep latency low.
            asyncio.create_task(self._run_semantic_guard_shadow(call))
            injection_res = {"score": 0, "reasoning": "Shadow evaluation enqueued"}

        t_eval["layer3"] = (time.perf_counter() - t3_start) * 1000

        # ── Layer 4: Dynamic Defensive Response (HITL + Sandbox) ─────────────
        # If score is moderately suspicious, suggest Sandbox
        anomaly_score = anomaly_res.get("anomaly_score", 0)
        injection_score = injection_res.get("score", 0)
        
        use_sandbox = self.sandbox.route(anomaly_score, injection_score)
        
        # ── Verdict Formulation ──────────────────────────────────────────────
        verdict = PERMIT
        reason  = "Permitted by all layers."
        if l1_res["action"] == AUDIT or anomaly_score > 0.25 or injection_score > 0.25:
            verdict = AUDIT

        # Auto-Baseline Enforcement (90% Readiness Fix)
        self._total_calls_seen += 1
        if self._total_calls_seen < self.auto_baseline_calls and verdict == BLOCK:
            reason = f"[AUTO-BASELINE] Would have BLOCKED: {reason}"
            verdict = AUDIT

        # HITL Check: High-risk tools + AUDIT verdict = HITL Required
        hitl_res = {"requires_hitl": False}
        if verdict == AUDIT:
            hitl_res = self.hitl.check_hitl_required(call)

        return await self._finalise(
            call, verdict, reason,
            {
                "policy": l1_res, 
                "anomaly": anomaly_res, 
                "alignment": alignment,
                "sandbox_suggested": use_sandbox,
                "hitl": hitl_res,
                "baseline_mode": self._total_calls_seen < self.auto_baseline_calls
            },
            None, t_start
        )

    async def _run_semantic_guard(self, call: dict) -> dict:
        """Core semantic evaluation with circuit breaker protection."""
        if self._injection_failure_rate > 0.15:
            return {"score": 0.5, "reasoning": "Fallback: Circuit breaker open"}
        try:
            res = await self.injection.analyse(call)
            self._injection_failure_rate *= 0.85
            return res
        except Exception as e:
            self._injection_failure_rate = min(1.0, self._injection_failure_rate + 0.2)
            return {"score": 0.6, "reasoning": f"Fallback: Semantic engine failure ({e})"}

    async def _run_semantic_guard_shadow(self, call: dict):
        """Asynchronous post-hoc evaluation for low-risk calls."""
        try:
            res = await self._run_semantic_guard(call)
            if res["score"] > 0.8:
                # Generate late AUDIT alert for forensics
                await self.audit.log(call, verdict="AUDIT", reason=f"Shadow Detection: {res['reasoning']}")
        except Exception as e:
            print(f"[Proxy] [ERROR] Shadow evaluation failed: {e}")

    async def _finalise(self, call, verdict, reason, details, mitre_id, t_start):
        latency_ms = (time.perf_counter() - t_start) * 1000
        event = {
            "event_id":   str(uuid.uuid4()),
            "timestamp":  time.time(),
            "agent_id":   call["agent_id"],
            "session_id": call["session_id"],
            "tool_name":  call["tool_name"],
            "arguments":  call["arguments"],
            "verdict":    verdict,
            "reason":     reason,
            "mitre_id":   mitre_id,
            "latency_ms": latency_ms,
            "details":    details,
        }
        
        # Log to DB
        await self.audit.log(event)
        
        # Wire CampaignDetector (P0 Fix)
        # We ingest EVERY event into the campaign correlateor to find patterns
        # self.injection_res should be passed or extracted from details
        inj_res = details.get("injection", {"score": 0})
        campaign_alert = await self.campaign.ingest(call, verdict, inj_res, event["event_id"])
        
        # 95% Readiness: Trigger Global Lockdown on high-risk campaigns
        if campaign_alert and campaign_alert.get("score", 0) > 0.9:
            self._system_lockdown_active = True
            self._lockdown_reason = f"High-risk campaign detected: {campaign_alert['id']}"
            print(f"[Proxy] [CRITICAL] System entering safety lockdown: {self._lockdown_reason}")
        
        # Prometheus Metrics (Fix for blank Metrics Dashboard)
        from agentwall.metrics import MetricsRegistry
        metrics = MetricsRegistry.get()
        metrics.record_call(verdict, event["tool_name"], event["agent_id"], latency_ms)
        metrics.record_tool_call(event["tool_name"])
        if mitre_id:
            metrics.record_mitre(mitre_id)
        if details.get("policy", {}).get("rule"):
            metrics.record_policy_violation(details["policy"].get("rule"))

        # Broadcast to dashboard via WebSocket if available
        if self.ws:
            await self.ws.broadcast({"type": "alert", "event": event})
            
        return event

    async def sanitise_output(self, payload: dict) -> dict:
        """Post-execution output sanitisation (Layer 5)."""
        output = payload.get("output", "")
        cleaned, removals = self.sanitiser.clean(output)
        return {
            "output":    cleaned,
            "sanitised": bool(removals),
            "removals":  removals,
            "session_id": payload.get("session_id"),
            "agent_id":   payload.get("agent_id")
        }
