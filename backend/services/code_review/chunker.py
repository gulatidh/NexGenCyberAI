"""
Code chunker: splits source files into function/class-level chunks for LLM analysis.

Uses Python's built-in `ast` for .py files and regex heuristics for JS/TS/Go/Java/etc.
Falls back to line-count based chunking with overlap when syntax parsing isn't available.
"""
from __future__ import annotations
import ast
import os
import re
from dataclasses import dataclass
from typing import List, Optional

SUPPORTED_EXTENSIONS: dict[str, str] = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
    ".cs": "csharp",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".rs": "rust",
    ".kt": "kotlin", ".kts": "kotlin",
    ".swift": "swift",
    ".sh": "bash", ".bash": "bash",
    ".tf": "terraform",
    ".yaml": "yaml", ".yml": "yaml",
}

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "env",
    "dist", "build", "target", ".next", ".nuxt", "vendor",
    "coverage", ".coverage", "htmlcov", ".mypy_cache", ".pytest_cache",
    ".tox", "migrations", "alembic", "staticfiles", "media",
    ".terraform", ".serverless",
}

# Files likely to contain sensitive logic — examined first
HIGH_RISK_PATTERNS = re.compile(
    r"(auth|login|password|secret|crypto|encrypt|jwt|token|session|"
    r"admin|privilege|permission|role|sql|query|exec|eval|shell|"
    r"upload|deserializ|marshal|parse|request|route|endpoint|api|"
    r"config|setting|credential|key|cert|tls|ssl)",
    re.IGNORECASE,
)

MAX_CHUNK_LINES = 200   # ≈3 000 tokens
OVERLAP_LINES = 25
MAX_FILE_BYTES = 250_000


@dataclass
class CodeChunk:
    file_path: str        # relative to repo root
    language: str
    function_name: str    # function/class name or "lines N–M"
    start_line: int
    end_line: int
    code: str
    imports: str          # top-of-file import block for context

    @property
    def token_estimate(self) -> int:
        return len(self.code) // 4


# ── File discovery ────────────────────────────────────────────────────────────

def get_file_tree(repo_dir: str, max_files: int = 600) -> list[str]:
    """Return relative paths of all source files, skip known noise directories."""
    files: list[str] = []
    for root, dirs, filenames in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if ext in SUPPORTED_EXTENSIONS:
                rel = os.path.relpath(os.path.join(root, fname), repo_dir)
                files.append(rel)
                if len(files) >= max_files:
                    return files
    return files


def score_file_risk(rel_path: str) -> int:
    """Heuristic risk score for triage ordering (higher = review first)."""
    score = 0
    name = rel_path.lower()
    if HIGH_RISK_PATTERNS.search(name):
        score += 10
    if any(name.endswith(s) for s in ("route.py", "routes.py", "views.py", "controller.py",
                                       "handler.py", "endpoint.py", "api.py")):
        score += 8
    if "test" in name or "spec" in name:
        score -= 5   # tests rarely introduce exploitable vulns
    return score


def detect_language(file_path: str) -> Optional[str]:
    return SUPPORTED_EXTENSIONS.get(os.path.splitext(file_path)[1].lower())


# ── Helpers ───────────────────────────────────────────────────────────────────

def _read_safe(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read(MAX_FILE_BYTES)
    except Exception:
        return None


def _extract_imports(content: str, language: str) -> str:
    lines = content.splitlines()
    out: list[str] = []
    for line in lines[:100]:
        s = line.strip()
        if language == "python" and (s.startswith("import ") or s.startswith("from ")):
            out.append(line)
        elif language in ("javascript", "typescript") and (
            "require(" in s or s.startswith("import ")
        ):
            out.append(line)
        elif language in ("java", "kotlin") and s.startswith("import "):
            out.append(line)
        elif language == "go" and (s.startswith("import") or s.startswith('"')):
            out.append(line)
        elif language == "csharp" and s.startswith("using "):
            out.append(line)
        if len(out) >= 40:
            break
    return "\n".join(out)


# ── Python chunking via ast ───────────────────────────────────────────────────

def _chunk_python(abs_path: str, rel_path: str) -> list[CodeChunk]:
    content = _read_safe(abs_path)
    if not content:
        return []
    imports = _extract_imports(content, "python")
    lines = content.splitlines()
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return _chunk_by_lines(rel_path, "python", content)

    nodes = [
        n for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    ]
    # Only keep top-level and immediate class members (depth ≤ 2)
    top_nodes = [n for n in nodes if hasattr(n, "col_offset") and n.col_offset < 8]

    chunks: list[CodeChunk] = []
    for node in top_nodes:
        start = node.lineno - 1
        end = getattr(node, "end_lineno", min(start + 60, len(lines)))
        chunk_lines = lines[start:end]
        _split_into_chunks(chunk_lines, node.name, rel_path, "python", imports, start, chunks)

    return chunks or _chunk_by_lines(rel_path, "python", content)


# ── Regex-based chunking for other languages ──────────────────────────────────

_FUNC_PATTERNS: dict[str, re.Pattern] = {
    "javascript": re.compile(
        r"^\s*(export\s+)?(default\s+)?(async\s+)?function\b|"
        r"^\s*(const|let|var)\s+\w+\s*=\s*(async\s*)?\(|"
        r"^\s*(export\s+)?class\s+"
    ),
    "typescript": re.compile(
        r"^\s*(export\s+)?(default\s+)?(async\s+)?function\b|"
        r"^\s*(public|private|protected|static|async|override)[\s]+|"
        r"^\s*(const|let|var)\s+\w+\s*=\s*(async\s*)?\(|"
        r"^\s*(export\s+)?(abstract\s+)?class\s+"
    ),
    "go":    re.compile(r"^func\s+"),
    "java":  re.compile(r"^\s+(public|private|protected|static|void|@Override)\b"),
    "kotlin":re.compile(r"^\s*(fun\s+|class\s+|object\s+|companion\s+object)"),
    "csharp":re.compile(r"^\s+(public|private|protected|static|override|virtual|async)\b"),
    "ruby":  re.compile(r"^\s*def\s+|^\s*class\s+"),
    "rust":  re.compile(r"^\s*(pub\s+)?(async\s+)?fn\s+|^\s*(pub\s+)?impl\s+"),
    "php":   re.compile(r"^\s*(public|protected|private|static|function)\b"),
    "swift": re.compile(r"^\s*(func|class|struct|enum|extension)\s+"),
}


def _chunk_by_regex(rel_path: str, content: str, language: str) -> list[CodeChunk]:
    pat = _FUNC_PATTERNS.get(language)
    if not pat:
        return []
    imports = _extract_imports(content, language)
    lines = content.splitlines()
    starts = [i for i, line in enumerate(lines) if pat.search(line)]
    if len(starts) < 2:
        return []
    chunks: list[CodeChunk] = []
    for idx, start in enumerate(starts):
        end = starts[idx + 1] if idx + 1 < len(starts) else len(lines)
        chunk_lines = lines[start:end]
        m = re.search(r"\b(\w+)\s*[\(\{<]", lines[start])
        func_name = m.group(1) if m else f"block_{start + 1}"
        _split_into_chunks(chunk_lines, func_name, rel_path, language, imports, start, chunks)
    return chunks


def _chunk_by_lines(rel_path: str, language: str, content: str) -> list[CodeChunk]:
    imports = _extract_imports(content, language)
    lines = content.splitlines()
    chunks: list[CodeChunk] = []
    step = MAX_CHUNK_LINES - OVERLAP_LINES
    for i in range(0, len(lines), step):
        cl = lines[i:i + MAX_CHUNK_LINES]
        chunks.append(CodeChunk(
            file_path=rel_path, language=language,
            function_name=f"lines {i + 1}–{i + len(cl)}",
            start_line=i + 1, end_line=i + len(cl),
            code="\n".join(cl), imports=imports,
        ))
    return chunks


def _split_into_chunks(
    chunk_lines: list[str], name: str, rel_path: str,
    language: str, imports: str, base_line: int,
    out: list[CodeChunk],
) -> None:
    if len(chunk_lines) <= MAX_CHUNK_LINES:
        out.append(CodeChunk(
            file_path=rel_path, language=language, function_name=name,
            start_line=base_line + 1, end_line=base_line + len(chunk_lines),
            code="\n".join(chunk_lines), imports=imports,
        ))
    else:
        step = MAX_CHUNK_LINES - OVERLAP_LINES
        for i in range(0, len(chunk_lines), step):
            sub = chunk_lines[i:i + MAX_CHUNK_LINES]
            part = i // step + 1
            out.append(CodeChunk(
                file_path=rel_path, language=language,
                function_name=f"{name} (part {part})",
                start_line=base_line + i + 1, end_line=base_line + i + len(sub),
                code="\n".join(sub), imports=imports,
            ))


# ── Public API ────────────────────────────────────────────────────────────────

def chunk_file(abs_path: str, rel_path: str) -> list[CodeChunk]:
    """Chunk one source file into function/class-level segments."""
    language = detect_language(rel_path)
    if not language:
        return []
    if language == "python":
        return _chunk_python(abs_path, rel_path)
    content = _read_safe(abs_path)
    if not content:
        return []
    chunks = _chunk_by_regex(rel_path, content, language)
    return chunks or _chunk_by_lines(rel_path, language, content)


def chunk_files(repo_dir: str, rel_paths: list[str]) -> list[CodeChunk]:
    """Chunk a list of files; returns all chunks sorted by file then position."""
    all_chunks: list[CodeChunk] = []
    for rel in rel_paths:
        abs_path = os.path.join(repo_dir, rel)
        all_chunks.extend(chunk_file(abs_path, rel))
    return all_chunks
