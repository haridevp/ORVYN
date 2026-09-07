from typing import List, Dict, Any
import json
from models_db import SessionLocal
from memory_service import MemoryService

MCP_TOOLS = [
    {
        "name": "get_target_scan_history",
        "description": "Returns the historical scan timeline and summary for a given target.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "The name or URL of the target to query"
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "diff_last_two_scans",
        "description": "Generates a delta report (New, Persistent, Resolved findings) between the last two scans of a target.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "The name or URL of the target to diff"
                }
            },
            "required": ["target"]
        }
    }
]

class MCPBridge:
    def __init__(self):
        pass
        
    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> str:
        db = SessionLocal()
        try:
            memory_service = MemoryService(db)
            if tool_name == "get_target_scan_history":
                target = arguments.get("target")
                if not target:
                    return "Error: missing target parameter"
                timeline = memory_service.get_timeline(target)
                return json.dumps([t.model_dump() for t in timeline], indent=2)
                
            elif tool_name == "diff_last_two_scans":
                target = arguments.get("target")
                if not target:
                    return "Error: missing target parameter"
                try:
                    delta = memory_service.diff_last_two_scans(target)
                    return delta.model_dump_json(indent=2)
                except ValueError as e:
                    return f"Error: {str(e)}"
            else:
                return f"Error: Unknown tool {tool_name}"
        finally:
            db.close()
