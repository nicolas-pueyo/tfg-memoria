# cybeross_pipeline.py
from pydantic import BaseModel
import requests


OLLAMA_HOST = "http://[protegido]:11434"
RAG_API_URL = "http://172.17.0.1:9000/query-context"

class Valves(BaseModel):
    model: str = "cybeross"
    context_profile: str = "large"

class Pipeline:
    id = "cybeross-rag"
    name = "CyberOSS RAG"

    valves = Valves()

    def pipe(self, body, **kwargs):
        messages = body.get("messages", [])

        kwargs.pop("messages", None)
        kwargs.pop("model", None)

        result = self.run(messages=messages, **kwargs)

        yield result

    def run(self, messages=None, model=None, **kwargs):
        messages = messages or []

        selected_model, context_profile = self._get_config(kwargs)

        print(f"[CyberOSS pipeline] Selected model: {selected_model}", flush = True)
        print(f"[CyberOSS pipeline] Context profile: {context_profile}", flush = True)

        user_query = self._extract_last_user_message(messages)

        if not user_query:
            return "No input"

        internal_response = self._handle_openwebui_task(user_query)
        if internal_response is not None:
            print("[Lily pipeline] OpenWebUI internal task detected, bypassing RAG", flush=True)
            return internal_response


        rag_context = self._get_rag_context(
            query=user_query,
            context_profile=context_profile
        )

        cybeross_prompt = self._build_cybeross_prompt(
            rag_context=rag_context,
            user_query=user_query
        )

        answer = self._call_cybeross(
            model=selected_model,
            prompt=cybeross_prompt
        )

        return answer

    def _get_config(self, kwargs):
        valves = kwargs.get("values") or self.valves

        if isinstance(valves, dict):
            selected_model = valves.get("model") or self.valves.model
            context_profile = valves.get("context_profile") or self.valves.context_profile
        else:
            selected_model = valves.model
            context_profile = valves.context_profile

        return selected_model, context_profile

    def _extract_last_user_message(self, messages):
        for msg in reversed(messages):
            if msg.get("role") == "user":
                return msg.get("content", "")
        return ""

    def _get_rag_context(self, query, context_profile):
        response = requests.post(
            RAG_API_URL,
            json={
                "query": query,
                "context_profile": context_profile
            },
            timeout=180
        )

        response.raise_for_status()

        return response.json()["context"]

    def _build_cybeross_prompt(self, rag_context, user_query):
        analysis_prompt = f"""
You are a cyber threat intelligence analyst.

Use ALL the information provided in the context.

Instructions:
- First, extract ALL explicit indicators and facts
- Then. describe all CTI entities mentioned, incluiding threat actors, reports, malware, campaings, techniques, infrastructure or any other CTI objects
- Then, explain what relationships are clearly prsent and what remains uncertain.

Rules:
- Do NOT invent information
- Do NOT ignore any part of the context
- If something is unclear, say it clearly.
- Clearly distinguish factual OpenCTI intelligence from inferred/contextual information.
- Write a clear, natural and structured explanation.

### CONTEXT
{rag_context}

### QUESTION
{user_query}
""".strip()

        return self._wrap_for_cybeross(analysis_prompt)

    def _wrap_for_cybeross(self, text):
        return f"""<|start|>user
{text}
<|end|>
<|start|>assistante
"""

    def _call_cybeross(self, model, prompt):
        response = requests.post(
            f"{OLLAMA_HOST}/api/chat",
            json={
                "model": model,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "stream": False,
                "options": {
                    "temperature": 0.2,
                    "stop": [
                        "<|end|>",
                        "<|start|>user"
                    ]
                }
            },
            timeout=300
        )

        response.raise_for_status()

        data = response.json()

        return data["message"]["content"].strip()

    def _handle_openwebui_task(self, user_query: str):
        q = (user_query or "").lower()

        if (
            "follow_ups" in q
            or "follow-up" in q
            or "follow up" in q
            or "relevant follow-up" in q
        ):
            return '{"follow_ups": []}'

        if (
            "tags" in q
            or "generate tags" in q
            or "suggest tags" in q
            or "chat tags" in q
        ):
            return '{"tags": []}'

        if (
            "generate a concise" in q
            and "title" in q
        ):
            return "Análisis indicador CTI"

        if (
            "<chat_history>" in q
            or "chat_history" in q
            or "summarize the conversation" in q
            or "conversation summary" in q
        ):
            return ""

        return None
