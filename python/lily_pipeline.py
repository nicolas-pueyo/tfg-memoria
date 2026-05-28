# lily_pipeline.py
from pydantic import BaseModel
import requests

OLLAMA_HOST = "http://[protegido]:11434"
RAG_API_URL = "http://172.17.0.1:9000/query-context"


class Valves(BaseModel):
    model: str = "lily-cyber"
    context_profile: str = "small"

class Pipeline:
    id = "lily-rag"
    name = "Lily RAG"

    valves = Valves()

    def pipe(self, body, **kwargs):
        messages = body.get("messages", [])

        kwargs.pop("messages", None)
        kwargs.pop("model", None)

        result = self.run(messages=messages, **kwargs)

        yield result

    def run(self, messages=None, model=None, **kwargs):
        valves = kwargs.get("valves") or self.valves

        selected_model, context_profile = self._get_config(kwargs)

        print(f"[Lily pipeline] Selected model: {selected_model}", flush=True)
        print(f"[Lily pipeline] Context profile: {context_profile}", flush=True)

        user_query = self._extract_user_query(messages)
        if not user_query:
            return {
                "role": "assistant",
                "content": "No input"
            }

        internal_response = self._handle_openwebui_task(user_query)
        if internal_response is not None:
            print("[Lily pipeline] OpenWebUI internal task detected, bypassing RAG", flush=True)
            return internal_response

        rag_context = self._get_rag_context(
            query=user_query,
            context_profile=context_profile
        )

        final_messages = self._build_lily_messages(
            messages=messages,
            rag_context=rag_context,
            user_query=user_query
        )

        data = self._call_lily(
            model=selected_model,
            messages=final_messages
        )

        return data["message"]["content"]

    def _get_config(self, kwargs):
        valves = kwargs.get("valves") or self.valves

        if isinstance(valves, dict):
            selected_model = valves.get("model") or self.valves.model
            context_profile = valves.get("context_profile") or self.valves.context_profile
        else:
            selected_model = valves.model
            context_profile = valves.context_profile

        return selected_model, context_profile

    def _extract_user_query(self, messages):
        user_query = ""

        for msg in reversed(messages):
            if msg.get("role") == "user":
                user_query = msg.get("content", "")
                break

        return user_query


    def _get_rag_context(self, query, context_profile):
        resp = requests.post(
            RAG_API_URL,
            json={
                "query": query,
                "context_profile": context_profile
            },
            timeout=180
        )

        resp.raise_for_status()

        return resp.json()["context"]

    def _build_lily_messages(self, messages, rag_context, user_query):
        return [
            {
                "role": "system",
                "content": self._build_lily_system_prompt(
                    rag_context=rag_context,
                    user_query=user_query
                )
            }
        ] + messages

    def _build_lily_system_prompt(self, rag_context, user_query):
        return f"""
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
"""

    def _call_lily(self, model, messages):
        response = requests.post(
            f"{OLLAMA_HOST}/api/chat",
            json={
                "model": model,
                "messages": messages,
                "stream": False
            },
            timeout=300
        )

        response.raise_for_status()
        return response.json()

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
