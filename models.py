from sqlmodel import SQLModel, Field
from sqlalchemy import Column, String
from typing import Optional

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(sa_column=Column(String(50), nullable=False))
    email: str = Field(sa_column=Column(String(100), unique=True, nullable=False))
    password: str = Field(sa_column=Column(String(255), nullable=False))