from functools import lru_cache
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from firmwarex.config import settings

@lru_cache
def factory():
    return sessionmaker(create_engine(settings().database_url, pool_pre_ping=True), expire_on_commit=False)

def session():
    with factory()() as db:
        yield db
