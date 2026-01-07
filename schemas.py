from pydantic import BaseModel, EmailStr, field_validator, Field
from typing import Optional, List


class SignupSchema(BaseModel):
    name: str
    email: EmailStr
    password: str
    confirmPassword: str
    role: str = Field(default="mother", description="User role: mother or contributor")

    @field_validator("confirmPassword")
    def passwords_match(cls, v, info):
        password = info.data.get("password") if info and getattr(info, "data", None) else None
        if password is not None and v != password:
            raise ValueError("Passwords do not match")
        return v


class LoginSchema(BaseModel):
    email: EmailStr
    password: str


class ChangePasswordSchema(BaseModel):
    oldPassword: str
    newPassword: str


class ForgotPasswordSchema(BaseModel):
    email: EmailStr


class ResetPasswordSchema(BaseModel):
    token: str
    newPassword: str


class UpdateNameSchema(BaseModel):
    name: str


class EPDSAnswerSchema(BaseModel):
    """
    Schema for EPDS screening submission.
    Each question answer should be 0, 1, 2, or 3.
    """
    q1: int  # I have been able to laugh and see the funny side of things
    q2: int  # I have looked forward with enjoyment to things
    q3: int  # I have blamed myself unnecessarily when things went wrong
    q4: int  # I have been anxious or worried for no good reason
    q5: int  # I have felt scared or panicky for no very good reason
    q6: int  # Things have been getting on top of me
    q7: int  # I have been so unhappy that I have had difficulty sleeping
    q8: int  # I have felt sad or miserable
    q9: int  # I have been so unhappy that I have been crying
    q10: int  # The thought of harming myself has occurred to me
    
    @field_validator('q1', 'q2', 'q3', 'q4', 'q5', 'q6', 'q7', 'q8', 'q9', 'q10')
    def validate_answer(cls, v):
        if v not in [0, 1, 2, 3]:
            raise ValueError('Each answer must be 0, 1, 2, or 3')
        return v


# Blog Schemas
class TOCObject(BaseModel):
    name: str
    value: str


class BlogCreateSchema(BaseModel):
    title: str = Field(..., max_length=60, description="Blog title (max 60 characters)")
    slug: str = Field(..., description="URL-friendly slug")
    meta: str = Field(..., max_length=160, description="SEO meta description (max 160 characters)")
    desc: str = Field(..., description="HTML content of blog")
    preview: Optional[str] = Field(None, description="JSON string of layout")
    cover: str = Field(..., description="Image URL")
    cover_key: str = Field(..., description="S3/storage key")
    tags: List[str] = Field(..., min_items=1, description="Array of tags (min 1)")
    category: List[str] = Field(..., min_items=1, description="Array of categories (min 1)")
    toc: Optional[List[TOCObject]] = Field(None, description="Table of contents")
    
    @field_validator('title')
    def validate_title(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('Title is required')
        if len(v) > 60:
            raise ValueError('Title must be 60 characters or less')
        return v.strip()
    
    @field_validator('slug')
    def validate_slug(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('Slug is required')
        # Basic URL-friendly validation
        if not all(c.isalnum() or c in '-_' for c in v):
            raise ValueError('Slug must be URL-friendly (alphanumeric, hyphens, underscores only)')
        return v.strip().lower()
    
    @field_validator('meta')
    def validate_meta(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('Meta description is required')
        if len(v) > 160:
            raise ValueError('Meta description must be 160 characters or less')
        return v.strip()


class BlogUpdateSchema(BaseModel):
    title: Optional[str] = Field(None, max_length=60)
    slug: Optional[str] = None
    meta: Optional[str] = Field(None, max_length=160)
    desc: Optional[str] = None
    preview: Optional[str] = None
    cover: Optional[str] = None
    cover_key: Optional[str] = None
    tags: Optional[List[str]] = Field(None, min_items=1)
    category: Optional[List[str]] = Field(None, min_items=1)
    toc: Optional[List[TOCObject]] = None
    
    @field_validator('title', mode='before')
    def validate_title(cls, v):
        if v is not None:
            if len(v.strip()) == 0:
                raise ValueError('Title cannot be empty')
            if len(v) > 60:
                raise ValueError('Title must be 60 characters or less')
            return v.strip()
        return v
    
    @field_validator('slug', mode='before')
    def validate_slug(cls, v):
        if v is not None:
            if len(v.strip()) == 0:
                raise ValueError('Slug cannot be empty')
            if not all(c.isalnum() or c in '-_' for c in v):
                raise ValueError('Slug must be URL-friendly')
            return v.strip().lower()
        return v
    
    @field_validator('meta', mode='before')
    def validate_meta(cls, v):
        if v is not None:
            if len(v.strip()) == 0:
                raise ValueError('Meta description cannot be empty')
            if len(v) > 160:
                raise ValueError('Meta description must be 160 characters or less')
            return v.strip()
        return v


class CreatedBySchema(BaseModel):
    id: str
    name: str


class BlogListItemSchema(BaseModel):
    id: str
    title: str
    slug: str
    cover: str
    isPublished: bool
    tags: List[str]
    category: List[str]
    createdBy: CreatedBySchema
    createdAt: str
    meta: str


class BlogDetailSchema(BaseModel):
    id: str
    title: str
    slug: str
    cover: str
    cover_key: str
    meta: str
    desc: str
    preview: Optional[str]
    tags: List[str]
    category: List[str]
    toc: Optional[List[TOCObject]]
    isPublished: bool
    createdBy: CreatedBySchema
    createdAt: str


# Community Post Schemas
class CreatePostSchema(BaseModel):
    title: str
    body: str
    tags: List[str]
    categoryId: str
    isAnonymous: bool
    image: Optional[str] = None


class CategoryResponseSchema(BaseModel):
    id: str
    name: str


class UserResponseSchema(BaseModel):
    id: str
    name: str
    role: Optional[str] = None


class ViewPostResponseSchema(BaseModel):
    id: str
    title: str
    body: str
    image: Optional[str]
    tags: List[str]
    category: CategoryResponseSchema
    isAnonymous: bool
    user: UserResponseSchema
    postedTime: str


class CreateCategorySchema(BaseModel):
    name: str


class UpdatePostSchema(BaseModel):
    title: Optional[str] = None
    body: Optional[str] = None
    tags: Optional[List[str]] = None
    categoryId: Optional[str] = None
    isAnonymous: Optional[bool] = None
    image: Optional[str] = None


# Group Schemas
class CreateGroupSchema(BaseModel):
    groupName: str
    groupDescription: str
    categoryId: str
    image: Optional[str] = None


class UpdateGroupSchema(BaseModel):
    groupName: Optional[str] = None
    groupDescription: Optional[str] = None
    categoryId: Optional[str] = None
    image: Optional[str] = None


class ViewGroupResponseSchema(BaseModel):
    groupId: str
    groupName: str
    groupDescription: str
    image: Optional[str]
    category: CategoryResponseSchema
    createdBy: UserResponseSchema
    createdAt: str


# Group Post Schemas
class CreateGroupPostSchema(BaseModel):
    postTitle: str
    postBody: str
    tags: List[str]
    categoryId: str
    isAnonymous: bool
    image: Optional[str] = None
    groupId: str


class UpdateGroupPostSchema(BaseModel):
    postTitle: Optional[str] = None
    postBody: Optional[str] = None
    tags: Optional[List[str]] = None
    categoryId: Optional[str] = None
    isAnonymous: Optional[bool] = None
    image: Optional[str] = None


class ViewGroupPostResponseSchema(BaseModel):
    id: str
    groupId: str
    postTitle: str
    postBody: str
    image: Optional[str]
    tags: List[str]
    isAnonymous: bool
    category: CategoryResponseSchema
    user: UserResponseSchema
    postedTime: str


# ==================== COMMENT SCHEMAS ====================


class CreateCommentSchema(BaseModel):
    postId: str  # e.g. "post_1" or "1"
    text: str
    parentCommentId: Optional[str] = Field(
        default=None,
        description="Optional. Set to comment ID (e.g. 'comment_5') to create a reply"
    )


class ViewCommentUserSchema(BaseModel):
    id: str
    name: str
    role: Optional[str] = None


class ViewCommentSchema(BaseModel):
    id: str
    postId: str
    parentCommentId: Optional[str]
    text: str
    user: ViewCommentUserSchema
    likeCount: int
    hasLiked: bool
    createdAt: str


class CreateGroupCommentSchema(BaseModel):
    postId: str  # e.g. "post_1" or "1"
    text: str
    parentCommentId: Optional[str] = Field(
        default=None,
        description="Optional. Set to comment ID (e.g. 'comment_5') to create a reply"
    )


class ViewGroupCommentSchema(BaseModel):
    id: str
    postId: str
    parentCommentId: Optional[str]
    text: str
    user: ViewCommentUserSchema
    likeCount: int
    hasLiked: bool
    createdAt: str

