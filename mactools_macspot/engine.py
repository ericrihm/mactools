"""macspot analysis engine — natural language translation and index health."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from mactools_core.spotlight import IndexStatus, get_index_status


# ---------------------------------------------------------------------------
# Natural-language → mdfind predicate heuristics
# ---------------------------------------------------------------------------

# Each entry: (pattern, predicate_template)
# Pattern is matched case-insensitively against the full query.
_NL_RULES: list[tuple[re.Pattern[str], str]] = [
    # File-type keywords
    (re.compile(r"\bpdf[s]?\b", re.IGNORECASE),
     'kMDItemContentType == "com.adobe.pdf"'),
    (re.compile(r"\bimage[s]?\b|\bphoto[s]?\b|\bjpeg[s]?\b|\bpng[s]?\b", re.IGNORECASE),
     'kMDItemContentTypeTree == "public.image"'),
    (re.compile(r"\bvideo[s]?\b|\bmovie[s]?\b|\bmp4[s]?\b|\bm4v[s]?\b", re.IGNORECASE),
     'kMDItemContentTypeTree == "public.movie"'),
    (re.compile(r"\baudio[s]?\b|\bmusic\b|\bmp3[s]?\b|\bm4a[s]?\b", re.IGNORECASE),
     'kMDItemContentTypeTree == "public.audio"'),
    (re.compile(r"\bspreadsheet[s]?\b|\bexcel\b|\bxlsx?\b", re.IGNORECASE),
     'kMDItemContentTypeTree == "public.spreadsheet"'),
    (re.compile(r"\bpresentation[s]?\b|\bpowerpoint\b|\bpptx?\b", re.IGNORECASE),
     'kMDItemContentTypeTree == "public.presentation"'),
    (re.compile(r"\bword\b|\bdocx?\b|\bdocument[s]?\b", re.IGNORECASE),
     'kMDItemContentTypeTree == "public.text"'),
    (re.compile(r"\bfolder[s]?\b|\bdirector(?:y|ies)\b", re.IGNORECASE),
     'kMDItemContentType == "public.folder"'),
    (re.compile(r"\bapp(?:lication)?[s]?\b", re.IGNORECASE),
     'kMDItemContentType == "com.apple.application-bundle"'),
    (re.compile(r"\barchive[s]?\b|\bzip[s]?\b|\btar[s]?\b", re.IGNORECASE),
     'kMDItemContentTypeTree == "public.archive"'),
    (re.compile(r"\bsource\s*code\b|\bcode\b|\bscript[s]?\b", re.IGNORECASE),
     'kMDItemContentTypeTree == "public.source-code"'),
]

# Temporal modifiers: (pattern, date_predicate_suffix)
_TIME_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\btoday\b", re.IGNORECASE),
     "kMDItemFSContentChangeDate >= $time.today"),
    (re.compile(r"\bthis\s+week\b|\bpast\s+week\b|\blast\s+7\s+days?\b", re.IGNORECASE),
     "kMDItemFSContentChangeDate >= $time.this_week"),
    (re.compile(r"\bthis\s+month\b|\bpast\s+month\b|\blast\s+30\s+days?\b", re.IGNORECASE),
     "kMDItemFSContentChangeDate >= $time.this_month"),
    (re.compile(r"\bthis\s+year\b|\bpast\s+year\b", re.IGNORECASE),
     "kMDItemFSContentChangeDate >= $time.this_year"),
    (re.compile(r"\byesterday\b", re.IGNORECASE),
     "kMDItemFSContentChangeDate >= $time.yesterday"),
]

# Modifiers that refine results
_LARGE_FILE_PATTERN = re.compile(r"\blarge\b|\bbig\b|\bheavy\b", re.IGNORECASE)
_AUTHOR_PATTERN = re.compile(r"\bby\s+(.+?)(?:\s+modified|\s+created|\s+from|\s*$)", re.IGNORECASE)
_NAME_PATTERN = re.compile(r"\bnamed?\s+['\"]?(.+?)['\"]?(?:\s+modified|\s+in|\s*$)", re.IGNORECASE)


def natural_language_to_predicate(query: str) -> str:
    """Translate a natural-language query into an mdfind predicate string.

    Uses heuristic pattern matching.  Returns a best-effort predicate — falls
    back to a full-text kMDItemTextContent search when nothing more specific
    can be inferred.

    Examples::

        natural_language_to_predicate("PDFs modified this week")
        # → 'kMDItemContentType == "com.adobe.pdf" && kMDItemFSContentChangeDate >= $time.this_week'

        natural_language_to_predicate("large images from this year")
        # → 'kMDItemContentTypeTree == "public.image" && kMDItemFSContentChangeDate >= $time.this_year && kMDItemFSSize > 10485760'
    """
    parts: list[str] = []

    # File-type clause
    for pattern, predicate in _NL_RULES:
        if pattern.search(query):
            parts.append(predicate)
            break  # use first matching type only

    # Temporal clause
    for pattern, date_pred in _TIME_RULES:
        if pattern.search(query):
            parts.append(date_pred)
            break

    # Large-file clause
    if _LARGE_FILE_PATTERN.search(query):
        parts.append("kMDItemFSSize > 10485760")  # > 10 MB

    # Author clause
    author_match = _AUTHOR_PATTERN.search(query)
    if author_match:
        author = author_match.group(1).strip().strip("'\"")
        parts.append(f'kMDItemAuthors == "{author}"')

    # Explicit name clause
    name_match = _NAME_PATTERN.search(query)
    if name_match:
        name = name_match.group(1).strip().strip("'\"")
        parts.append(f'kMDItemDisplayName == "*{name}*"cd')

    # Fallback: full-text search on raw query
    if not parts:
        safe = query.replace('"', '\\"')
        return f'kMDItemTextContent == "{safe}"cdw'

    return " && ".join(parts)


# ---------------------------------------------------------------------------
# Index health
# ---------------------------------------------------------------------------

@dataclass
class IndexHealthReport:
    total_volumes: int
    enabled_count: int
    disabled_count: int
    issues: list[str]
    statuses: list[IndexStatus]

    @property
    def healthy(self) -> bool:
        return len(self.issues) == 0


def audit_index_health(statuses: Optional[list[IndexStatus]] = None) -> IndexHealthReport:
    """Check Spotlight index health across all volumes.

    Flags disabled or stale indexes.  Pass a pre-fetched list of
    :class:`~mactools_core.spotlight.IndexStatus` objects, or *None* to fetch
    them automatically.
    """
    if statuses is None:
        statuses = get_index_status()

    issues: list[str] = []
    enabled_count = 0
    disabled_count = 0

    for s in statuses:
        if s.enabled:
            enabled_count += 1
        else:
            disabled_count += 1
            issues.append(f"Spotlight indexing DISABLED on {s.volume}")

        # Flag stale — mdutil sometimes reports "Indexing enabled" but also
        # "Index is disabled" in the status line (edge case with exclusions).
        if "disabled" in s.status.lower() and s.enabled:
            issues.append(f"Inconsistent index state on {s.volume}: {s.status}")

    return IndexHealthReport(
        total_volumes=len(statuses),
        enabled_count=enabled_count,
        disabled_count=disabled_count,
        issues=issues,
        statuses=statuses,
    )
