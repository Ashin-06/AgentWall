class SandboxRouter:
    """
    Dynamic Sandbox Routing.
    Determines if a tool call should be sent to a safe, isolated environment 
    instead of the production environment.
    """
    def route(self, anomaly_score: float, injection_score: float) -> bool:
        # Route to sandbox if scores are moderately suspicious
        if (0.5 <= anomaly_score <= 0.75) or (0.4 <= injection_score <= 0.6):
            return True
        return False
