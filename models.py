from sqlmodel import SQLModel, Field
from sqlalchemy import Column, String, Integer, DateTime, Text, Boolean, ARRAY, JSON
from typing import Optional, List
from datetime import datetime

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(sa_column=Column(String(50), nullable=False))
    email: str = Field(sa_column=Column(String(100), unique=True, nullable=False))
    password: str = Field(sa_column=Column(String(255), nullable=False))
    role: str = Field(sa_column=Column(String(20), nullable=False, default="mother"))


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


class Category(SQLModel, table=True):
    """Model to store community post categories"""
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(sa_column=Column(String(100), unique=True, nullable=False))
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime, nullable=False))


class CommunityPost(SQLModel, table=True):
    """Model to store community posts/feeds"""
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str = Field(sa_column=Column(String(200), nullable=False))
    body: str = Field(sa_column=Column(Text, nullable=False))
    image: Optional[str] = Field(default=None, sa_column=Column(String(500)))  # Image URL
    tags: str = Field(sa_column=Column(Text, nullable=False))  # JSON array as string ["tag1", "tag2"]
    category_id: int = Field(foreign_key="category.id", nullable=False)
    post_type: bool = Field(default=True, sa_column=Column(Boolean, nullable=False))  # True for public, False for private
    user_id: int = Field(foreign_key="user.id", nullable=False)
    like_count: int = Field(default=0, sa_column=Column(Integer, nullable=False))  # Stored like count
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime, nullable=False))


class Group(SQLModel, table=True):
    """Model to store community groups"""
    id: Optional[int] = Field(default=None, primary_key=True)
    group_name: str = Field(sa_column=Column(String(200), nullable=False))
    group_description: str = Field(sa_column=Column(Text, nullable=False))
    image: Optional[str] = Field(default=None, sa_column=Column(String(500)))  # Image URL
    category_id: int = Field(foreign_key="category.id", nullable=False)
    created_by_id: int = Field(foreign_key="user.id", nullable=False)
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime, nullable=False))


class GroupMember(SQLModel, table=True):
    """Model to track group memberships"""
    id: Optional[int] = Field(default=None, primary_key=True)
    group_id: int = Field(foreign_key="group.id", nullable=False)
    user_id: int = Field(foreign_key="user.id", nullable=False)
    joined_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime, nullable=False))


class GroupPost(SQLModel, table=True):
    """Model to store posts within groups"""
    id: Optional[int] = Field(default=None, primary_key=True)
    post_title: str = Field(sa_column=Column(String(200), nullable=False))
    post_body: str = Field(sa_column=Column(Text, nullable=False))
    image: Optional[str] = Field(default=None, sa_column=Column(String(500)))  # Image URL
    tags: str = Field(sa_column=Column(Text, nullable=False))  # JSON array as string ["tag1", "tag2"]
    category_id: int = Field(foreign_key="category.id", nullable=False)
    post_type: bool = Field(default=True, sa_column=Column(Boolean, nullable=False))  # True for public, False for private
    group_id: int = Field(foreign_key="group.id", nullable=False)
    user_id: int = Field(foreign_key="user.id", nullable=False)
    like_count: int = Field(default=0, sa_column=Column(Integer, nullable=False))  # Stored like count
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime, nullable=False))


class CommunityPostLike(SQLModel, table=True):
    """Likes on community posts"""
    id: Optional[int] = Field(default=None, primary_key=True)
    post_id: int = Field(foreign_key="communitypost.id", nullable=False)
    user_id: int = Field(foreign_key="user.id", nullable=False)
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime, nullable=False))


class GroupPostLike(SQLModel, table=True):
    """Likes on group posts"""
    id: Optional[int] = Field(default=None, primary_key=True)
    post_id: int = Field(foreign_key="grouppost.id", nullable=False)
    user_id: int = Field(foreign_key="user.id", nullable=False)
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime, nullable=False))


class CommunityComment(SQLModel, table=True):
    """Comments (and replies) on community posts"""
    id: Optional[int] = Field(default=None, primary_key=True)
    post_id: int = Field(foreign_key="communitypost.id", nullable=False)
    user_id: int = Field(foreign_key="user.id", nullable=False)
    text: str = Field(sa_column=Column(Text, nullable=False))
    parent_comment_id: Optional[int] = Field(
        default=None,
        sa_column=Column(Integer, nullable=True)
    )  # Null for top-level comments, set for replies
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime, nullable=False))


class GroupComment(SQLModel, table=True):
    """Comments (and replies) on group posts"""
    id: Optional[int] = Field(default=None, primary_key=True)
    post_id: int = Field(foreign_key="grouppost.id", nullable=False)
    user_id: int = Field(foreign_key="user.id", nullable=False)
    text: str = Field(sa_column=Column(Text, nullable=False))
    parent_comment_id: Optional[int] = Field(
        default=None,
        sa_column=Column(Integer, nullable=True)
    )
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime, nullable=False))


class CommunityCommentLike(SQLModel, table=True):
    """Likes on community comments (including replies)"""
    id: Optional[int] = Field(default=None, primary_key=True)
    comment_id: int = Field(foreign_key="communitycomment.id", nullable=False)
    user_id: int = Field(foreign_key="user.id", nullable=False)
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime, nullable=False))


class GroupCommentLike(SQLModel, table=True):
    """Likes on group comments (including replies)"""
    id: Optional[int] = Field(default=None, primary_key=True)
    comment_id: int = Field(foreign_key="groupcomment.id", nullable=False)
    user_id: int = Field(foreign_key="user.id", nullable=False)
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime, nullable=False))