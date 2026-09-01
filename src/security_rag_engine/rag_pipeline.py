import json
import logging
from typing import List, Dict, Any
from openai import OpenAI
from config import LM_STUDIO_URL, MODEL_NAME, TEMPERATURE
from database import get_collection
from schemas import ScannerFinding, TriageResult

logger = logging.getLogger(__name__)

class SecurityRAGPipeline:
    def __init__(self):
        self.collection = get_collection()
        self.client = OpenAI(base_url=LM_STUDIO_URL, api_key="lm-studio")
        self.model = MODEL_NAME
        
    def retrieve_context(self, finding: ScannerFinding, top_k: int = 3) -> List[Dict[str, Any]]:
        query_text = f"{finding.vulnerability}\n{finding.description}\n{finding.evidence or ''}"
        
        try:
            results = self.collection.query(
                query_texts=[query_text],
                n_results=top_k
            )
            
            contexts = []
            if results and 'documents' in results and results['documents']:
                for i in range(len(results['documents'][0])):
                    doc = results['documents'][0][i]
                    meta = results['metadatas'][0][i]
                    contexts.append({
                        "content": doc,
                        "reference": meta.get("reference", "")
                    })
            return contexts
        except Exception as e:
            logger.error(f"Error retrieving context from vector DB: {e}")
            return []

    def construct_prompt(self, finding: ScannerFinding, contexts: List[Dict[str, Any]]) -> tuple[str, str]:
        context_str = ""
        for i, ctx in enumerate(contexts):
            context_str += f"--- Context {i+1} ---\n{ctx['content']}\nReference: {ctx['reference']}\n\n"
            
        system_prompt = (
            "You are an expert cybersecurity triage AI. "
            "Your job is to analyze vulnerability scanner findings using the provided knowledge base context "
            "and output a structured JSON response. ONLY output valid JSON. Do not include markdown formatting or backticks.\n\n"
            "The JSON must follow this exact structure:\n"
            "{\n"
            '  "target": "string",\n'
            '  "vulnerability": "string",\n'
            '  "validated_severity": "string (Critical, High, Medium, Low, Info)",\n'
            '  "confidence_score": integer (0 to 100),\n'
            '  "threat_explanation": "string",\n'
            '  "remediation_guidance": "string",\n'
            '  "retrieved_references": ["string"],\n'
            '  "status": "Triaged"\n'
            "}"
        )
        
        user_prompt = (
            f"Please triage the following scanner finding.\n\n"
            f"Scanner Finding:\n"
            f"Tool: {finding.tool}\n"
            f"Target: {finding.target}\n"
            f"Vulnerability: {finding.vulnerability}\n"
            f"Reported Severity: {finding.severity}\n"
            f"Description: {finding.description}\n"
            f"Evidence: {finding.evidence or 'None'}\n\n"
            f"Retrieved Context:\n{context_str}\n"
        )
        
        return system_prompt, user_prompt

    def _strip_json(self, response: str) -> str:
        response = response.strip()
        if response.startswith("```json"):
            response = response[7:]
        elif response.startswith("```"):
            response = response[3:]
            
        if response.endswith("```"):
            response = response[:-3]
            
        return response.strip()

    def triage_finding(self, finding: ScannerFinding) -> TriageResult:
        contexts = self.retrieve_context(finding)
        references = [ctx["reference"] for ctx in contexts if ctx["reference"]]
        
        system_prompt, user_prompt = self.construct_prompt(finding, contexts)
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=TEMPERATURE
            )
            
            raw_content = response.choices[0].message.content
            cleaned_json = self._strip_json(raw_content)
            
            try:
                data = json.loads(cleaned_json)
            except json.JSONDecodeError as je:
                logger.error(f"JSON Parsing Error. Raw output: {raw_content}")
                raise je
            
            # Ensure references from DB are included if LLM missed them
            if not data.get("retrieved_references"):
                data["retrieved_references"] = references
                
            return TriageResult(**data)
            
        except Exception as e:
            logger.error(f"Error during triage LLM call or JSON parsing: {e}")
            # Fallback mechanism
            return TriageResult(
                target=finding.target,
                vulnerability=finding.vulnerability,
                validated_severity=finding.severity,
                confidence_score=0,
                threat_explanation=f"Triage failed due to error: {str(e)}",
                remediation_guidance="Please review manually.",
                retrieved_references=[],
                status="Error"
            )
