from fastapi import APIRouter

from src.api.v1.branches import router as branches_router
from src.api.v1.cves import router as cves_router
from src.api.v1.matrix import router as matrix_router
from src.api.v1.plan import router as plan_router
from src.api.v1.scans import router as scans_router
from src.api.v1.events import router as events_router
from src.api.v1.jira import router as jira_router

v1_router = APIRouter()
v1_router.include_router(branches_router)
v1_router.include_router(cves_router)
v1_router.include_router(matrix_router)
v1_router.include_router(plan_router)
v1_router.include_router(scans_router)
v1_router.include_router(events_router)
v1_router.include_router(jira_router)
