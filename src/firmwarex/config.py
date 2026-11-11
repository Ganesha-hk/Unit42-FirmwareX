from functools import lru_cache
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="FWX_")
    database_url: str
    redis_url: str = "redis://redis:6379/0"
    storage: Path = Path("/data")
    host_storage: str = ""
    static_image: str = "firmwarex-static:day1"
    emulation_image: str = "firmwarex-qemu:task3"
    pipeline_image: str = "firmwarex-pipeline:task5"
    mentor_authorized_execution: bool = False
    api_token: str
    company_registration_code: str = ""
    session_cookie_secure: bool = False
    max_upload_bytes: int = 128 * 1024 * 1024
    max_pending_jobs: int = 16
    job_wall_seconds: int = 180
    job_cpu_seconds: int = 120
    job_memory_bytes: int = 768 * 1024 * 1024
    sandbox_uid: int = 1000
    sandbox_gid: int = 1000

@lru_cache
def settings():
    return Settings()
