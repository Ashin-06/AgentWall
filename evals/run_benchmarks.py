import os
import sys
import json
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Isolate deterministic Layer 1 evaluation from deployment state.
os.environ["AGENTWALL_DB"] = ":memory:"
os.environ["AGENTWALL_ADMIN_PASSWORD"] = "test_evals"
os.environ["AGENTWALL_AUTH_ENABLED"] = "0"
os.environ["AGENTWALL_SHADOW_MODE"] = "0"
os.environ["DATABASE_URL"] = ""
os.environ["REDIS_URL"] = ""
os.environ["AGENTWALL_POLICY_PROFILE"] = "standard"
os.environ["AGENTWALL_EVAL_MODE"] = "eval"

from fastapi.testclient import TestClient
from agentwall.main import app
from agentwall.audit.schema import init_db

def load_dataset(filepath: str) -> list:
    dataset = []
    with open(filepath, 'r') as f:
        for line in f:
            if line.strip():
                dataset.append(json.loads(line.strip()))
    return dataset

def run_eval():
    init_db()
    
    print("[*] AgentWall Security Evaluation Suite")
    print("="*60)
    
    # Load Datasets
    evals_dir = os.path.dirname(os.path.abspath(__file__))
    benign_data = load_dataset(os.path.join(evals_dir, "datasets", "benign.jsonl"))
    malicious_data = load_dataset(os.path.join(evals_dir, "datasets", "malicious.jsonl"))
    
    from unittest.mock import patch, AsyncMock, Mock
    with patch("agentwall.layer2.trust_graph.TrustGraph.check_delegation", return_value={"action": "PERMIT", "reason": "mock"}), \
         patch("agentwall.layer2.causal_graph.CausalGraphDetector.analyse", return_value={"is_attack_chain": False}), \
         patch("agentwall.layer2.anomaly.TemporalAnomalyDetector.score", return_value={"anomaly_score": 0.0, "is_anomaly": False}), \
         patch("agentwall.layer2.rag_detector.RAGPoisoningDetector.check", return_value={"score": 0.0, "reasoning": "mock"}), \
         patch("agentwall.layer3.injection.LLMInjectionClassifier.analyse", new_callable=AsyncMock, return_value={"score": 0.0, "reasoning": "mock"}), \
         patch("agentwall.rbac.RBACEngine.check", return_value={"allowed": True}), \
         patch("agentwall.layer4.campaign.CampaignDetector.ingest", new_callable=AsyncMock, return_value=None), \
         patch("agentwall.audit.system_watcher.start_system_watcher", return_value=Mock()), \
         TestClient(app) as client:
        
        print(f"Loaded {len(benign_data)} Benign samples and {len(malicious_data)} Malicious samples.")
        print("-" * 60)
        
        # Benchmarking Benign Data
        print("[*] Testing Benign Traffic (Measuring False Positives)...")
        false_positives = 0
        benign_blocks = 0
        missed_policy_denials = 0
        # These non-malicious fixtures are intentionally forbidden by the
        # shipped policy: relative writes outside allowed roots and code exec.
        expected_denials = {"c4", "c5", "c9", "c12", "c18", "c22"}
        benign_latencies = []
        
        for idx, payload in enumerate(benign_data):
            payload["session_id"] = f"EVAL_B_{idx}_{int(time.time())}"
            t_start = time.time()
            resp = client.post("/intercept", json=payload)
            resp.raise_for_status()
            lat = time.time() - t_start
            benign_latencies.append(lat)
            
            data = resp.json()
            if data.get("verdict") == "BLOCK":
                benign_blocks += 1
                if payload["call_id"] not in expected_denials:
                    false_positives += 1
                    print(f"Unexpected block #{idx + 1}: {data.get('reason', 'No reason')}")
            elif payload["call_id"] in expected_denials:
                missed_policy_denials += 1
                
        # Benchmarking Malicious Data
        print("[*] Testing Malicious Traffic (Measuring True Positives)...")
        true_positives = 0
        malicious_latencies = []
        
        for idx, payload in enumerate(malicious_data):
            payload["session_id"] = f"EVAL_M_{idx}_{int(time.time())}"
            t_start = time.time()
            resp = client.post("/intercept", json=payload)
            resp.raise_for_status()
            lat = time.time() - t_start
            malicious_latencies.append(lat)
            
            data = resp.json()
            if data.get("verdict") == "BLOCK":
                true_positives += 1
                
        # Calculations
        fpr = (false_positives / len(benign_data)) * 100
        tpr = (true_positives / len(malicious_data)) * 100
        avg_lat = (sum(benign_latencies) + sum(malicious_latencies)) / (len(benign_data) + len(malicious_data)) * 1000
        
        print("\n" + "="*60)
        print("[*] FINAL BENCHMARK RESULTS")
        print("="*60)
        print(f"True Positive Rate (TPR) : {tpr:.2f}% (Target: >90%)")
        print(f"Benign fixture block rate: {benign_blocks / len(benign_data) * 100:.2f}% ({benign_blocks}/{len(benign_data)}; 6 expected policy denials)")
        print(f"Unexpected block rate    : {fpr:.2f}% (Target: <10%)")
        print(f"Average Latency          : {avg_lat:.2f} ms")
        print("="*60)
        
        # GitHub Action Threshold Enforcement
        success = True
        if tpr < 90:
            print("[FAIL] TPR is below 90% threshold.")
            success = False
        if fpr > 10:
            print("[FAIL] Unexpected block rate is above 10% threshold.")
            success = False
        if missed_policy_denials:
            print(f"[FAIL] {missed_policy_denials} expected policy denials were permitted.")
            success = False
            
        if not success:
            sys.exit(1)
        else:
            print("[PASS] Security Evals Passed Successfully.")
            sys.exit(0)

if __name__ == "__main__":
    run_eval()
