"""
Cloud Native Adapters.
These adapters allow AgentWall to sit in front of managed cloud services
like AWS Bedrock or Azure OpenAI directly, intercepting native API payloads.
"""

class BedrockAdapter:
    @staticmethod
    def extract_tools(request_payload: dict) -> list[dict]:
        """Extract tool use calls from an AWS Bedrock Converse API payload."""
        # This is a stub for the Bedrock Converse API structure
        tools = []
        messages = request_payload.get("messages", [])
        for msg in messages:
            for content in msg.get("content", []):
                if "toolUse" in content:
                    tu = content["toolUse"]
                    tools.append({
                        "tool_name": tu.get("name"),
                        "arguments": tu.get("input", {}),
                        "call_id": tu.get("toolUseId")
                    })
        return tools

class AzureOpenAIAdapter:
    @staticmethod
    def extract_tools(request_payload: dict) -> list[dict]:
        """Extract tool use calls from an Azure OpenAI completions payload."""
        # Azure OpenAI structure is mostly identical to standard OpenAI
        tools = []
        messages = request_payload.get("messages", [])
        for msg in messages:
            if "tool_calls" in msg:
                for tc in msg["tool_calls"]:
                    tools.append({
                        "tool_name": tc.get("function", {}).get("name"),
                        "arguments": tc.get("function", {}).get("arguments", "{}"),
                        "call_id": tc.get("id")
                    })
        return tools
