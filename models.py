from sqlmodel import SQLModel, Field
from sqlalchemy import Column, String, Integer, DateTime, Text, Boolean, ARRAY, JSON
from typing import Optional, List
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


class Blog(SQLModel, table=True):
    """Model to store blog posts"""
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str = Field(sa_column=Column(String(60), nullable=False))
    slug: str = Field(sa_column=Column(String(100), unique=True, nullable=False))
    meta: str = Field(sa_column=Column(String(160), nullable=False))  # SEO meta description
    desc: str = Field(sa_column=Column(Text, nullable=False))  # HTML content
    preview: Optional[str] = Field(default=None, sa_column=Column(Text))  # JSON string of layout
    cover: str = Field(sa_column=Column(String(500), nullable=False))  # Image URL
    cover_key: str = Field(sa_column=Column(String(500), nullable=False))  # S3/storage key
    tags: str = Field(sa_column=Column(Text, nullable=False))  # JSON array as string ["tag1", "tag2"]
    category: str = Field(sa_column=Column(Text, nullable=False))  # JSON array as string ["cat1"]
    toc: Optional[str] = Field(default=None, sa_column=Column(Text))  # JSON array as string
    is_published: bool = Field(default=False, sa_column=Column(Boolean, nullable=False))
    created_by_id: int = Field(foreign_key="user.id", nullable=False)
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime, nullable=False))
    updated_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime))