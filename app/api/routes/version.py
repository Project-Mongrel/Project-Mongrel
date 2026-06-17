from pydantic import BaseModel

from fastapi import APIRouter, Depends

from app.core.config import Settings, get_settings


class VersionResponse(BaseModel):
    name: str
    version: str
    environment: str


router = APIRouter()


@router.get("/version", response_model=VersionResponse)
async def version(settings: Settings = Depends(get_settings)) -> VersionResponse:
    return VersionResponse(
        name=settings.app_name,
        version=settings.app_version,
        environment=settings.app_env,
    )
