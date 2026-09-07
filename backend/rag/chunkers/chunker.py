"""
Chunking strategies for knowledge base ingestion.

- chunk_text(): sliding-window, sentence-aware chunking for short/medium docs
  (CVE, CWE, MITRE ATT&CK descriptions)
- chunk_markdown_by_headers(): splits markdown docs by ## headers first,
  then sub-chunks any section still too large (OWASP cheat sheets)
"""

import re


def chunk_text(text, max_chars=1000, overlap=100):
    """
    Sliding-window chunker with sentence-aware breaks.
    If text fits in one chunk, returns it as-is (no unnecessary splitting).
    """
    text = text.strip()
    if len(text) <= max_chars:
        return [text]

    chunks = []
    start = 0
    text_len = len(text)
    min_chunk_size = int(max_chars * 0.5)  # don't accept a break point that's "too early"

    while start < text_len:
        end = min(start + max_chars, text_len)

        if end < text_len:
            # try to break at a sentence boundary, but only accept it if
            # it's not absurdly close to `start` (else we barely progress)
            last_period = text.rfind(". ", start + min_chunk_size, end)
            if last_period != -1:
                end = last_period + 1
            else:
                last_space = text.rfind(" ", start + min_chunk_size, end)
                if last_space != -1:
                    end = last_space
            # if neither found, just hard-cut at max_chars (already the case)

        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)

        if end >= text_len:
            break

        # always advance by at least (max_chars - overlap) to guarantee progress
        next_start = end - overlap
        start = max(next_start, start + (max_chars - overlap))

    return chunks


def chunk_markdown_by_headers(md_text, max_chars=1200, overlap=100):
    """
    Split markdown by level-2 headers, then sub-chunk oversized sections.
    """
    md_text = md_text.strip()
    if not md_text:
        return []

    sections = re.split(r'\n(?=##\s)', md_text)
    chunks = []

    for section in sections:
        section = section.strip()
        if not section:
            continue

        if len(section) <= max_chars:
            chunks.append(section)
            continue

        lines = section.split('\n', 1)
        header = lines[0] if lines[0].startswith('#') else ''
        body = lines[1] if len(lines) > 1 else section

        for index, sub_chunk in enumerate(
            chunk_text(body, max_chars=max_chars, overlap=overlap)
        ):
            chunks.append(
                f'{header}\n{sub_chunk}' if header and index > 0 else sub_chunk
            )

    return [chunk.strip() for chunk in chunks if chunk.strip()]


def strip_markdown_noise(text):
    """
    Light cleanup for markdown before chunking: removes code fence markers
    and excessive blank lines that don't add retrieval value, while keeping
    actual code content (useful for cheat sheets with example snippets).
    """
    # collapse 3+ blank lines into 1
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()

def process_source(raw_entries, source_name, use_markdown_chunking=False,
                    max_chars=1000, overlap=100):
    """
    Converts a list of raw entries {source_id, title, text, url} into
    chunk records ready for ChromaDB: {id, document, metadata}.
    """
    processed = []
    chunk_fn = chunk_markdown_by_headers if use_markdown_chunking else chunk_text

    for entry in raw_entries:
        text = entry.get("text", "")
        if not text or not text.strip():
            continue

        pieces = chunk_fn(text, max_chars=max_chars, overlap=overlap)

        safe_id = re.sub(r'[^a-zA-Z0-9_-]', '-', entry["source_id"].lower())

        for i, piece in enumerate(pieces):
            processed.append({
                "id": f"{safe_id}-chunk-{i}",
                "document": piece,
                "metadata": {
                    "source": source_name,
                    "source_id": entry["source_id"],
                    "title": entry.get("title", ""),
                    "url": entry.get("url", ""),
                    "chunk_index": i,
                }
            })

    return processed