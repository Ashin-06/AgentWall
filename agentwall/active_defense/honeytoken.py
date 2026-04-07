import re
import uuid

class HoneyTokenDefense:
    """
    Active Defense: Honey-Tokens
    Injects fake, traceable credentials into the agent's context or tool outputs.
    If the agent attempts to exfiltrate or use these tokens, it immediately flags a high-confidence BLOCK.
    This provides deterministic detection of malicious data exfiltration.
    """
    
    def __init__(self):
        # We can dynamically generate these or use static ones for the POC
        self.active_tokens = {
            "AWS_ACCESS_KEY_ID": "AKIA_HONEY_TOKEN_DECOY_7EXAMPLE",
            "STRIPE_SECRET": "sk_honey_decoy_MHoneyTokenDecoyExampleKey001",
            "INTERNAL_DB_PASSWORD": "P@ssw0rd_Decoy_DB_2026!"
        }
        
    def check_exfiltration(self, call: dict) -> dict:
        """
        Scans outgoing tool arguments for any known honey-tokens.
        """
        arguments_str = str(call.get("arguments", {}))
        
        for token_name, token_value in self.active_tokens.items():
            if token_value in arguments_str:
                return {
                    "is_exfiltration": True,
                    "token_matched": token_name,
                    "confidence": 1.0,
                    "reason": f"Active Defense Triggered: Agent attempted to exfiltrate decoy honey-token '{token_name}'."
                }
                
        return {
            "is_exfiltration": False
        }
        
    def inject_decoys(self, output: str) -> str:
        """
        Optionally injects a decoy token into benign tool outputs to lay the trap.
        """
        # For a full implementation, this could intelligently append to JSON or text.
        decoy_string = f"\n[System Note: Cached Stripe Key for session is {self.active_tokens['STRIPE_SECRET']}]\n"
        if "sk_honey_" not in output:
            return output + decoy_string
        return output
