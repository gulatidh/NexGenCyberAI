"""RAG (Retrieval-Augmented Generation) service for customer security documents."""
import re
from typing import List, Tuple


_CHUNK_SIZE = 800   # chars per chunk
_CHUNK_OVERLAP = 100


def extract_text(content: bytes, filename: str, content_type: str) -> str:
    """Extract plain text from uploaded file. Supports PDF, DOCX, TXT."""
    fname = filename.lower()

    if fname.endswith(".txt") or "text/plain" in (content_type or ""):
        return content.decode("utf-8", errors="replace")

    if fname.endswith(".pdf") or "pdf" in (content_type or ""):
        try:
            import PyPDF2, io
            reader = PyPDF2.PdfReader(io.BytesIO(content))
            return "\n".join(page.extract_text() or "" for page in reader.pages)
        except ImportError:
            try:
                import pdfminer.high_level, io
                return pdfminer.high_level.extract_text(io.BytesIO(content))
            except ImportError:
                return content.decode("utf-8", errors="replace")

    if fname.endswith(".docx") or "wordprocessingml" in (content_type or ""):
        try:
            import docx, io
            doc = docx.Document(io.BytesIO(content))
            return "\n".join(p.text for p in doc.paragraphs)
        except ImportError:
            return content.decode("utf-8", errors="replace")

    # Fallback
    return content.decode("utf-8", errors="replace")


def chunk_text(text: str) -> List[str]:
    """Split text into overlapping chunks for retrieval."""
    text = re.sub(r'\n{3,}', '\n\n', text.strip())
    chunks = []
    start = 0
    while start < len(text):
        end = min(start + _CHUNK_SIZE, len(text))
        chunks.append(text[start:end])
        start += _CHUNK_SIZE - _CHUNK_OVERLAP
    return [c for c in chunks if c.strip()]


def rank_chunks(chunks: List[str], question: str, top_k: int = 5) -> List[Tuple[int, str]]:
    """Keyword-based chunk ranking (no embeddings needed)."""
    q_words = set(re.findall(r'\w+', question.lower()))
    scored = []
    for i, chunk in enumerate(chunks):
        c_words = set(re.findall(r'\w+', chunk.lower()))
        overlap = len(q_words & c_words)
        scored.append((overlap, i, chunk))
    scored.sort(reverse=True)
    return [(i, chunk) for _, i, chunk in scored[:top_k]]


async def query_documents(db, client_id: str, question: str) -> dict:
    """Answer a question using the client's uploaded documents via RAG."""
    from api.models.models import SecurityDocument
    from core.ai_providers import get_llm

    docs = db.query(SecurityDocument).filter(
        SecurityDocument.client_id == client_id,
        SecurityDocument.extracted_text.isnot(None),
    ).all()

    if not docs:
        return {"answer": "No documents have been uploaded yet. Please upload your security policies or documentation first.", "sources": []}

    all_chunks: List[Tuple[str, str]] = []  # (doc_name, chunk)
    for doc in docs:
        chunks = chunk_text(doc.extracted_text or "")
        for chunk in chunks:
            all_chunks.append((doc.filename, chunk))

    # Rank by relevance to question
    flat_chunks = [c for _, c in all_chunks]
    ranked = rank_chunks(flat_chunks, question, top_k=6)

    context_parts = []
    sources = []
    for idx, chunk in ranked:
        doc_name = all_chunks[idx][0] if idx < len(all_chunks) else "Unknown"
        context_parts.append(f"[From: {doc_name}]\n{chunk}")
        if doc_name not in sources:
            sources.append(doc_name)

    context = "\n\n---\n\n".join(context_parts)
    prompt = f"""You are a security analyst assistant. Answer the following question based ONLY on the provided document excerpts.
If the answer is not in the documents, say so clearly. Do not fabricate information.

Question: {question}

Document excerpts:
{context}

Answer:"""

    try:
        llm = get_llm()
        from langchain_core.messages import HumanMessage
        resp = await llm.ainvoke([HumanMessage(content=prompt)])
        answer = resp.content if hasattr(resp, "content") else str(resp)
    except Exception as exc:
        answer = f"AI query failed: {exc}. Here are the most relevant excerpts:\n\n{context[:1000]}"

    return {"answer": answer, "sources": sources, "chunks_used": len(ranked)}
