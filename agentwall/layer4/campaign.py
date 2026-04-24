"""
Distributed Campaign Detector using Redis.
Ensures attack correlation works across multiple pods in K8s.
"""
import time
import mmh3
import json
import os
import redis
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Optional

def simhash(text: str, bits: int = 64) -> int:
    if not isinstance(text, str): text = str(text)
    if not text: return 0
    v = [0] * bits
    words = text.lower().split()
    for word in words:
        h = mmh3.hash(word, signed=False)
        for i in range(bits):
            if h & (1 << i): v[i] += 1
            else: v[i] -= 1
    return sum(1 << i for i in range(bits) if v[i] > 0)

def hamming_distance(a: int, b: int) -> int:
    return bin(a ^ b).count("1")

SIMILARITY_THRESHOLD = 12
CAMPAIGN_MIN_SIZE    = 2

class CampaignDetector:
    _instance = None

    @classmethod
    def instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self.redis_url = os.getenv("REDIS_URL")
        self._r = None
        if self.redis_url:
            try:
                self._r = redis.from_url(self.redis_url, decode_responses=True)
                print(f"[CampaignDetector] Connected to Redis at {self.redis_url}")
            except Exception as e:
                print(f"[CampaignDetector] [FALLBACK] Redis failed: {e}")
        
        self._local_attempts = deque(maxlen=1000) # Fallback
        self._local_campaigns = {}

    async def ingest(self, call: dict, verdict: str, injection_result: dict, event_id: str):
        score = injection_result.get("score", 0)
        if score < 0.4 and verdict == "PERMIT": return None

        text = str(call.get("arguments", {}))[:500]
        fp = simhash(text)
        
        attempt = {
            "event_id": event_id,
            "session_id": call["session_id"],
            "agent_id": call["agent_id"],
            "fp": fp,
            "ts": time.time(),
            "verdict": verdict,
            "text": text[:100]
        }

        if self._r:
            return self._cluster_redis(attempt)
        else:
            return self._cluster_local(attempt)

    def _cluster_redis(self, attempt: dict) -> Optional[dict]:
        # Store attempt in a rolling window set
        self._r.zadd("attempts_stream", {json.dumps(attempt): attempt["ts"]})
        self._r.zremrangebyscore("attempts_stream", 0, time.time() - 86400) # 24h window

        # Find matching campaign
        campaign_keys = self._r.keys("campaign:CAMP-*")
        for key in campaign_keys:
            camp_data = json.loads(self._r.get(key))
            # Check last 5 attempts in campaign
            for prev in camp_data["attempts"][-5:]:
                if hamming_distance(attempt["fp"], prev["fp"]) <= SIMILARITY_THRESHOLD:
                    # Join campaign
                    camp_data["attempts"].append(attempt)
                    camp_data["last_seen"] = attempt["ts"]
                    camp_data["sessions"] = list(set(camp_data["sessions"] + [attempt["session_id"]]))
                    self._r.set(key, json.dumps(camp_data), ex=3600)
                    return camp_data

        # Check stream for a seed
        recent = self._r.zrangebyscore("attempts_stream", time.time() - 3600, time.time())
        for r_json in recent:
            prev = json.loads(r_json)
            if prev["event_id"] != attempt["event_id"] and hamming_distance(attempt["fp"], prev["fp"]) <= SIMILARITY_THRESHOLD:
                # Create new campaign
                cid = f"CAMP-{int(time.time())}-{mmh3.hash(attempt['event_id']) & 0xffff}"
                camp = {
                    "id": cid,
                    "first_seen": prev["ts"],
                    "last_seen": attempt["ts"],
                    "attempts": [prev, attempt],
                    "sessions": [prev["session_id"], attempt["session_id"]],
                    "score": 0.5
                }
                self._r.set(f"campaign:{cid}", json.dumps(camp), ex=3600)
                return camp
        return None

    def _cluster_local(self, attempt: dict) -> Optional[dict]:
        """Local clustering for standalone deployments (no Redis)."""
        # Find matching campaign in local memory
        for cid, camp in self._local_campaigns.items():
            # Check last 5 attempts in campaign for similarity
            for prev in camp["attempts"][-5:]:
                if hamming_distance(attempt["fp"], prev["fp"]) <= SIMILARITY_THRESHOLD:
                    camp["attempts"].append(attempt)
                    camp["last_seen"] = attempt["ts"]
                    camp["sessions"] = list(set(camp["sessions"] + [attempt["session_id"]]))
                    return camp

        # Check local sliding window for a similar seed to start a new campaign
        for prev in self._local_attempts:
            if prev["session_id"] != attempt["session_id"] and hamming_distance(attempt["fp"], prev["fp"]) <= SIMILARITY_THRESHOLD:
                # Create new campaign
                cid = f"CAMP-LOC-{int(time.time())}-{attempt['session_id'][:4]}"
                camp = {
                    "id": cid,
                    "first_seen": prev["ts"],
                    "last_seen": attempt["ts"],
                    "attempts": [prev, attempt],
                    "sessions": list(set([prev["session_id"], attempt["session_id"]])),
                    "score": 0.5
                }
                self._local_campaigns[cid] = camp
                return camp

        # No match found, store in sliding window for future potential seeds
        self._local_attempts.append(attempt)
        return None

    def get_active_campaigns(self) -> list[dict]:
        if self._r:
            keys = self._r.keys("campaign:CAMP-*")
            return [json.loads(self._r.get(k)) for k in keys]
        return list(self._local_campaigns.values())
