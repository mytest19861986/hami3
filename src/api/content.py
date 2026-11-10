"""
CMS & Informational Pages API Endpoints (CONTENT-001..005)
"""

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, status

from src.api.deps import get_db_pool
from src.content.service import ContentService, PageNotFoundError

router = APIRouter(prefix="/content", tags=["Content & CMS"])


@router.get("/pages/{slug}")
async def get_published_page(
    slug: str,
    pool: asyncpg.Pool = Depends(get_db_pool)
):
    """Retrieves published content page (e.g. terms, privacy, about-us, faq, contact)."""
    content_svc = ContentService(pool)
    try:
        return await content_svc.get_published_page(slug)
    except PageNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
