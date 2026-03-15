"""
Helix AI Security Agent — LangChain-powered orchestration.

Phase 1: LangChain chain with OpenAI GPT when OPENAI_API_KEY is set;
graceful template-based fallback otherwise.
Phase 2 extension: add LangGraph multi-agent workflows.
"""
from __future__ import annotations

import os
import importlib
from typing import List, Optional

from .prompt_templates import SYSTEM_PROMPT, SUMMARY_TEMPLATE
from .rag_store import retrieve_guidance

def _has_module(module_name: str) -> bool:
    """Return True when module can be imported at runtime."""
    try:
        importlib.import_module(module_name)
        return True
    except Exception:
        return False


_LANGCHAIN_AVAILABLE = _has_module("langchain")
_OPENAI_AVAILABLE = _has_module("langchain_openai") or _has_module("langchain")

# Build LangChain chain lazily
_chain: Optional[object] = None


def _build_chain() -> Optional[object]:
    """Build a LangChain LLMChain if dependencies and API key are available."""
    global _chain
    if _chain is not None:
        return _chain

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key or not _LANGCHAIN_AVAILABLE:
        return None

    try:
        if _OPENAI_AVAILABLE:
            try:
                ChatOpenAI = importlib.import_module("langchain_openai").ChatOpenAI
                llm = ChatOpenAI(model="gpt-4o-mini", temperature=0.3, openai_api_key=api_key)  # type: ignore[call-arg]
            except Exception:
                OpenAI = importlib.import_module("langchain.llms").OpenAI
                llm = OpenAI(temperature=0.3, openai_api_key=api_key)  # type: ignore[call-arg]

            PromptTemplate = importlib.import_module("langchain.prompts").PromptTemplate
            prompt = PromptTemplate(
                input_variables=["system", "context", "query"],
                template=(
                    "{system}\n\n"
                    "Relevant security guidance:\n{context}\n\n"
                    "Query: {query}\n\n"
                    "Provide a concise security recommendation and remediation roadmap:"
                ),
            )
            LLMChain = importlib.import_module("langchain.chains").LLMChain
            _chain = LLMChain(llm=llm, prompt=prompt)
            return _chain
    except Exception:
        pass

    return None


def run_security_agent(
    target: str,
    finding_titles: List[str],
    query: Optional[str] = None,
) -> dict:
    """
    Run Helix AI security agent.

    Uses LangChain + OpenAI when OPENAI_API_KEY is set.
    Falls back to RAG-only template response when LLM unavailable.
    """
    joined_findings = " ".join(finding_titles)
    query_text = query or joined_findings or target
    rag_results = retrieve_guidance(query_text, top_k=3)
    context = "\n- ".join(rag_results) if rag_results else "No specific guidance found."

    chain = _build_chain()
    if chain is not None:
        try:
            # LangChain chain invocation
            result = chain.run(  # type: ignore[union-attr]
                system=SYSTEM_PROMPT,
                context=context,
                query=query_text,
            )
            return {
                "target": target,
                "strategy": "LangChain + OpenAI GPT analysis",
                "actions": [line.strip() for line in str(result).splitlines() if line.strip()][:5],
                "rag_context": rag_results,
            }
        except Exception as exc:
            # Gracefully degrade on API errors
            pass

    # Template-based fallback (no OpenAI key or chain build failed)
    return {
        "target": target,
        "strategy": "RAG-assisted remediation planning (template mode)",
        "actions": rag_results[:3],
        "rag_context": rag_results,
    }
