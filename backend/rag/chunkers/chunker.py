"""
Chunking strategies for knowledge base ingestion.

- chunk_text(): sliding-window, sentence-aware chunking for short/medium docs
- chunk_markdown_by_headers(): splits markdown docs by ## headers first,
  then sub-chunks any section still too large
"""

# TODO: implement chunk_text() and chunk_markdown_by_headers()
