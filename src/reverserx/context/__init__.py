"""Source chunking, retrieval, embedding, and context budgeting."""

from reverserx.context.budget import PackedContext, RankedChunk, pack_context
from reverserx.context.chunking import SourceChunk, index_source_tree
from reverserx.context.search import LexicalSearchHit, SearchMode, lexical_search

__all__ = [
    "LexicalSearchHit",
    "PackedContext",
    "RankedChunk",
    "SearchMode",
    "SourceChunk",
    "index_source_tree",
    "lexical_search",
    "pack_context",
]
