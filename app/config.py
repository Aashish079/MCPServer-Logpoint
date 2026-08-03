import os
from typing import Dict, List

from pydantic import BaseSettings


class Settings(BaseSettings):
    jwt_secret: str = "a1b2c3d4e5f6g7h8i9j0k1"
    jwt_algorithm: str = "HS256"
    allowed_origins: List[str] = ["*"]
    environment: str = "development"
    allowed_users: List[str] = ["John:a1b2c3d4e5f6g7h8i9j0k1"]

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()

VALID_USERS: Dict[str, str] = {}
for item in settings.allowed_users:
    if ":" in item:
        username, secret = item.split(":", 1)
        VALID_USERS[username] = secret
