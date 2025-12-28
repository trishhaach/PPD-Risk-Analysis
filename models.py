from sqlmodel import SQLModel, Field
from sqlalchemy import Column, String, Integer, DateTime
from typing import Optional
from datetime import datetime

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(sa_column=Column(String(50), nullable=False))
    email: str = Field(sa_column=Column(String(100), unique=True, nullable=False))
    password: str = Field(sa_column=Column(String(255), nullable=False))


class EPDSResult(SQLModel, table=True):
    """Model to store EPDS screening results"""
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", nullable=False)
    
    # Individual question scores (0-3 each)
    q1: int = Field(sa_column=Column(Integer, nullable=False))
    q2: int = Field(sa_column=Column(Integer, nullable=False))
    q3: int = Field(sa_column=Column(Integer, nullable=False))
    q4: int = Field(sa_column=Column(Integer, nullable=False))
    q5: int = Field(sa_column=Column(Integer, nullable=False))
    q6: int = Field(sa_column=Column(Integer, nullable=False))
    q7: int = Field(sa_column=Column(Integer, nullable=False))
    q8: int = Field(sa_column=Column(Integer, nullable=False))
    q9: int = Field(sa_column=Column(Integer, nullable=False))
    q10: int = Field(sa_column=Column(Integer, nullable=False))
    
    # Calculated fields
    total_score: int = Field(sa_column=Column(Integer, nullable=False))
    risk_level: str = Field(sa_column=Column(String(20), nullable=False))  # low, moderate, high
    
    # Timestamp
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime, nullable=False))