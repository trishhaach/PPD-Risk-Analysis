from sqlmodel import SQLModel, Field
from sqlalchemy import Column, String, Integer, DateTime, Text, Boolean, ARRAY, JSON
from typing import Optional, List
from datetime import datetime
import uuid

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(sa_column=Column(String(50), nullable=False))
    email: str = Field(sa_column=Column(String(100), unique=True, nullable=False))
    password: str = Field(sa_column=Column(String(255), nullable=False))
    role: str = Field(sa_column=Column(String(20), nullable=False, default="mother"))
    is_verified: bool = Field(default=False, sa_column=Column(Boolean, nullable=False))


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


class PPDRiskAssessment(SQLModel, table=True):
    """
    Model to store ML-based PPD risk assessment results (symptom/questionnaire-based).
    Stores both the answers payload sent to the ML service and the ML response for auditing.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", nullable=False)
    ml_endpoint: Optional[str] = Field(default=None, sa_column=Column(String(500), nullable=True))
    answers_json: str = Field(sa_column=Column(Text, nullable=False))  # JSON string
    ml_response_json: str = Field(sa_column=Column(Text, nullable=False))  # JSON string
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


# ==================== Contributor Profile Models ====================

class ContributorProfile(SQLModel, table=True):
    """Step 1: Basic profile information for contributors"""
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", nullable=False, unique=True)
    first_name: str = Field(sa_column=Column(String(100), nullable=False))
    last_name: str = Field(sa_column=Column(String(100), nullable=False))
    professional_title: str = Field(sa_column=Column(String(200), nullable=False))
    short_bio: str = Field(sa_column=Column(Text, nullable=False))
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime, nullable=False))
    updated_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime, nullable=False))


class ContributorEducation(SQLModel, table=True):
    """Step 2: Education entries for contributors"""
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", nullable=False)
    education_id: str = Field(sa_column=Column(String(36), nullable=False))  # UUID as string
    institution_name: str = Field(sa_column=Column(String(200), nullable=False))
    degree: str = Field(sa_column=Column(String(200), nullable=False))
    year_of_graduation: str = Field(sa_column=Column(String(10), nullable=False))
    field_of_study: str = Field(sa_column=Column(String(200), nullable=False))
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime, nullable=False))
    updated_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime, nullable=False))


class ContributorExperience(SQLModel, table=True):
    """Step 3: Work experience entries for contributors"""
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", nullable=False)
    experience_id: str = Field(sa_column=Column(String(36), nullable=False))  # UUID as string
    job_title: str = Field(sa_column=Column(String(200), nullable=False))
    company_name: str = Field(sa_column=Column(String(200), nullable=False))
    start_month: int = Field(sa_column=Column(Integer, nullable=False))  # 1-12
    start_year: int = Field(sa_column=Column(Integer, nullable=False))
    end_month: Optional[int] = Field(default=None, sa_column=Column(Integer, nullable=True))  # 1-12 or null
    end_year: Optional[int] = Field(default=None, sa_column=Column(Integer, nullable=True))
    is_currently_working: bool = Field(sa_column=Column(Boolean, nullable=False))
    key_responsibilities: str = Field(sa_column=Column(Text, nullable=False))
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime, nullable=False))
    updated_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime, nullable=False))


class ContributorCertification(SQLModel, table=True):
    """Step 4: Certification entries for contributors"""
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", nullable=False)
    certification_id: str = Field(sa_column=Column(String(36), nullable=False))  # UUID as string
    certification_name: str = Field(sa_column=Column(String(200), nullable=False))
    issuing_organization: str = Field(sa_column=Column(String(200), nullable=False))
    date_issued: datetime = Field(sa_column=Column(DateTime, nullable=False))
    expiration_date: Optional[datetime] = Field(default=None, sa_column=Column(DateTime, nullable=True))
    credential_id: Optional[str] = Field(default=None, sa_column=Column(String(200), nullable=True))
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime, nullable=False))
    updated_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime, nullable=False))


class ContributorExpertise(SQLModel, table=True):
    """Step 5: Expertise topics for contributors"""
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", nullable=False)
    topic: str = Field(sa_column=Column(String(200), nullable=False))
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime, nullable=False))


class ContributorPublication(SQLModel, table=True):
    """Step 5: Publication entries for contributors"""
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", nullable=False)
    publication_id: str = Field(sa_column=Column(String(36), nullable=False))  # UUID as string
    title: str = Field(sa_column=Column(String(500), nullable=False))
    url: str = Field(sa_column=Column(String(1000), nullable=False))
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime, nullable=False))
    updated_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime, nullable=False))


class Article(SQLModel, table=True):
    """Model to store articles written by contributors"""
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str = Field(sa_column=Column(String(200), nullable=False))
    preview: str = Field(sa_column=Column(Text, nullable=False))
    content: str = Field(sa_column=Column(Text, nullable=False))
    image: str = Field(sa_column=Column(String(500), nullable=False))  # Image URL
    tags: str = Field(sa_column=Column(Text, nullable=False))  # JSON array as string ["tag1", "tag2"]
    category_id: int = Field(foreign_key="category.id", nullable=False)
    user_id: int = Field(foreign_key="user.id", nullable=False)
    status: str = Field(default="pending", sa_column=Column(String(20), nullable=False))  # "pending" or "published"
    like_count: int = Field(default=0, sa_column=Column(Integer, nullable=False))
    published_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime, nullable=True))
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime, nullable=False))
    updated_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime, nullable=False))


# ==================== Partner Invitation Models ====================

class PartnerInvite(SQLModel, table=True):
    """Model to store pending partner invitations"""
    id: Optional[int] = Field(default=None, primary_key=True)
    invite_code: str = Field(sa_column=Column(String(10), unique=True, nullable=False))  # Short random code
    mother_id: int = Field(foreign_key="user.id", nullable=False)
    partner_email: str = Field(sa_column=Column(String(100), nullable=False))
    permissions_json: str = Field(sa_column=Column(Text, nullable=False))  # JSON string with permissions
    expires_at: datetime = Field(sa_column=Column(DateTime, nullable=False))
    used: bool = Field(default=False, sa_column=Column(Boolean, nullable=False))
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime, nullable=False))


class MotherPartnerLink(SQLModel, table=True):
    """Model to store active links between mothers and partners"""
    id: Optional[int] = Field(default=None, primary_key=True)
    mother_id: int = Field(foreign_key="user.id", nullable=False)
    partner_id: int = Field(foreign_key="user.id", nullable=False)
    status: str = Field(default="active", sa_column=Column(String(20), nullable=False))  # "active" or "revoked"
    permissions_json: str = Field(sa_column=Column(Text, nullable=False))  # JSON string with permissions snapshot
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime, nullable=False))
    updated_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime, nullable=False))
    revoked_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime, nullable=True))


class PartnerAccessAudit(SQLModel, table=True):
    """Model to audit partner access to mother's screening data"""
    id: Optional[int] = Field(default=None, primary_key=True)
    partner_id: int = Field(foreign_key="user.id", nullable=False)
    mother_id: int = Field(foreign_key="user.id", nullable=False)
    access_type: str = Field(sa_column=Column(String(50), nullable=False))  # "summary", "history", "epds", "ppd", "hybrid"
    resource_id: Optional[int] = Field(default=None, sa_column=Column(Integer, nullable=True))  # Specific result ID if applicable
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime, nullable=False))