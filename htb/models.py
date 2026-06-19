from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator


class MachineInfo(BaseModel):
    id: int | None = None
    name: str
    ip: str | None = Field(default=None, alias="ip")
    os: str | None = None
    difficulty: str | None = None
    points: int | None = None
    retired: bool | None = None

    @field_validator("difficulty", mode="before")
    @classmethod
    def coerce_difficulty(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return value.get("text") or value.get("name")
        return value

    @classmethod
    def from_api(cls, payload: dict[str, Any]) -> "MachineInfo":
        data = payload.get("info") or payload.get("machine") or payload.get("data") or payload
        return cls.model_validate(data)


class UserInfo(BaseModel):
    id: int | None = None
    name: str | None = None
    rank: str | None = None
    points: int | None = None
