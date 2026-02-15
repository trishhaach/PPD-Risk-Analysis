from pydantic import BaseModel, EmailStr, field_validator, Field
from pydantic.config import ConfigDict
from typing import Optional, List, Dict, Any


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
    
    # Optional crisis resources context
    include_crisis_resources: bool = False
    city: Optional[str] = "Kathmandu"
    lat: Optional[float] = None
    lng: Optional[float] = None
    limit: int = Field(default=5, ge=1, le=10)
    
    @field_validator('q1', 'q2', 'q3', 'q4', 'q5', 'q6', 'q7', 'q8', 'q9', 'q10')
    def validate_answer(cls, v):
        if v not in [0, 1, 2, 3]:
            raise ValueError('Each answer must be 0, 1, 2, or 3')
        return v


# ==================== ML-based PPD Risk (Symptom Questionnaire) Schemas ====================

class PPDRiskAssessmentRequestSchema(BaseModel):
    """
    Request schema for ML-based PPD risk assessment.
    Uses field aliases that match the ML engineer's question IDs (including spaces and punctuation),
    so the frontend can send exactly the same keys the ML service expects.
    """
    model_config = ConfigDict(populate_by_name=True)
    
    # Optional crisis resources fields
    include_crisis_resources: bool = Field(default=False, description="Whether to include crisis resource recommendations")
    city: Optional[str] = Field(default="Kathmandu", description="City for crisis resource recommendations")
    lat: Optional[float] = Field(default=None, description="Latitude for distance calculation")
    lng: Optional[float] = Field(default=None, description="Longitude for distance calculation")
    limit: int = Field(default=5, ge=1, le=10, description="Maximum number of crisis resources to return")

    need_for_support: str = Field(alias="Need for Support")
    recieved_support: str = Field(alias="Recieved Support")
    abuse: str = Field(alias="Abuse")
    disease_before_pregnancy: str = Field(alias="Disease before pregnancy")
    occupation_before_latest_pregnancy: str = Field(alias="Occupation before latest pregnancy")
    pregnancy_plan: str = Field(alias="Pregnancy plan")
    relationship_with_husband: str = Field(alias="Relationship with husband")
    major_changes_or_losses_during_pregnancy: str = Field(alias="Major changes or losses during pregnancy")
    relationship_with_in_laws: str = Field(alias="Relationship with the in-laws")
    birth_compliancy: str = Field(alias="Birth compliancy")
    relationship_between_father_and_newborn: str = Field(alias="Relationship between father and newborn")
    education_level: str = Field(alias="Education Level")
    family_type: str = Field(alias="Family type")
    diseases_during_pregnancy: str = Field(alias="Diseases during pregnancy")
    trust_and_share_feelings: str = Field(alias="Trust and share feelings")
    relationship_with_newborn: str = Field(alias="Relationship with the newborn")
    occupation_after_latest_childbirth: str = Field(alias="Occupation After Your Latest Childbirth")
    age: float = Field(alias="Age", ge=18.0, le=45.0)
    addiction: str = Field(alias="Addiction")
    husbands_education_level: str = Field(alias="Husband's education level")

    @field_validator(
        "need_for_support",
        "recieved_support",
        "abuse",
        "disease_before_pregnancy",
        "occupation_before_latest_pregnancy",
        "pregnancy_plan",
        "relationship_with_husband",
        "major_changes_or_losses_during_pregnancy",
        "relationship_with_in_laws",
        "birth_compliancy",
        "relationship_between_father_and_newborn",
        "education_level",
        "family_type",
        "diseases_during_pregnancy",
        "trust_and_share_feelings",
        "relationship_with_newborn",
        "occupation_after_latest_childbirth",
        "addiction",
        "husbands_education_level",
    )
    def validate_non_empty(cls, v: str):
        if v is None or (isinstance(v, str) and len(v.strip()) == 0):
            raise ValueError("Field cannot be empty")
        return v


class PPDRiskAssessmentResponseSchema(BaseModel):
    id: str
    result: dict
    createdAt: str
    risk_level_standard: Optional[str] = Field(
        default=None,
        description="Standardized risk level: LOW, MEDIUM, HIGH, or CRITICAL"
    )
    recommended_articles: List["RecommendedArticleSchema"] = Field(
        default_factory=list,
        description="List of recommended articles based on this screening (max 2 for result page)"
    )
    recommendations_status: str = Field(
        description="Status of recommendation generation: 'ok' or 'unavailable'"
    )
    crisis_resources: Optional[List["CrisisResourceMiniOut"]] = Field(
        default=None,
        description="Recommended crisis resources (only included if include_crisis_resources=true in request)"
    )
    recommended_resource_ids: Optional[List[str]] = Field(
        default=None,
        description="IDs of recommended crisis resources stored in the database"
    )


class HybridScreeningRequestSchema(BaseModel):
    """
    Request schema for hybrid screening that combines EPDS and symptom-based ML assessment.
    """
    # EPDS responses (10 questions, each 0-3)
    epds_responses: List[int] = Field(..., min_length=10, max_length=10, description="List of 10 EPDS responses (integers 0-3)")
    
    # Symptom questionnaire answers (same as PPDRiskAssessmentRequestSchema)
    need_for_support: str = Field(alias="Need for Support")
    recieved_support: str = Field(alias="Recieved Support")
    abuse: str = Field(alias="Abuse")
    disease_before_pregnancy: str = Field(alias="Disease before pregnancy")
    occupation_before_latest_pregnancy: str = Field(alias="Occupation before latest pregnancy")
    pregnancy_plan: str = Field(alias="Pregnancy plan")
    relationship_with_husband: str = Field(alias="Relationship with husband")
    major_changes_or_losses_during_pregnancy: str = Field(alias="Major changes or losses during pregnancy")
    relationship_with_in_laws: str = Field(alias="Relationship with the in-laws")
    birth_compliancy: str = Field(alias="Birth compliancy")
    relationship_between_father_and_newborn: str = Field(alias="Relationship between father and newborn")
    education_level: str = Field(alias="Education Level")
    family_type: str = Field(alias="Family type")
    diseases_during_pregnancy: str = Field(alias="Diseases during pregnancy")
    trust_and_share_feelings: str = Field(alias="Trust and share feelings")
    relationship_with_newborn: str = Field(alias="Relationship with the newborn")
    occupation_after_latest_childbirth: str = Field(alias="Occupation After Your Latest Childbirth")
    age: float = Field(alias="Age", ge=18.0, le=45.0)
    addiction: str = Field(alias="Addiction")
    husbands_education_level: str = Field(alias="Husband's education level")
    
    # Optional crisis resources context
    include_crisis_resources: bool = False
    city: Optional[str] = "Kathmandu"
    lat: Optional[float] = None
    lng: Optional[float] = None
    limit: int = Field(default=5, ge=1, le=10)
    
    model_config = ConfigDict(populate_by_name=True)
    
    @field_validator('epds_responses')
    @classmethod
    def validate_epds_responses(cls, v):
        if len(v) != 10:
            raise ValueError("EPDS must have exactly 10 responses")
        if any(score < 0 or score > 3 for score in v):
            raise ValueError("Each EPDS response must be between 0 and 3")
        return v
    
    @field_validator(
        "need_for_support",
        "recieved_support",
        "abuse",
        "disease_before_pregnancy",
        "occupation_before_latest_pregnancy",
        "pregnancy_plan",
        "relationship_with_husband",
        "major_changes_or_losses_during_pregnancy",
        "relationship_with_in_laws",
        "birth_compliancy",
        "relationship_between_father_and_newborn",
        "education_level",
        "family_type",
        "diseases_during_pregnancy",
        "trust_and_share_feelings",
        "relationship_with_newborn",
        "occupation_after_latest_childbirth",
        "addiction",
        "husbands_education_level"
    )
    @classmethod
    def validate_non_empty(cls, v):
        if v is None or (isinstance(v, str) and len(v.strip()) == 0):
            raise ValueError("Field cannot be empty")
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


# ==================== Contributor Profile Schemas ====================

# Step 1: Basic Profile
class Step1BasicProfileSchema(BaseModel):
    first_name: str
    last_name: str
    professional_title: str
    short_bio: str


# Step 2: Education
class EducationItemSchema(BaseModel):
    education_id: str  # UUID
    institution_name: str
    degree: str
    year_of_graduation: str
    field_of_study: str


class Step2EducationSchema(BaseModel):
    education: List[EducationItemSchema]


# Step 3: Experience
class ExperienceItemSchema(BaseModel):
    experience_id: str  # UUID
    job_title: str
    company_name: str
    start_month: int = Field(..., ge=1, le=12)
    start_year: int
    end_month: Optional[int] = Field(None, ge=1, le=12)
    end_year: Optional[int] = None
    is_currently_working: bool
    key_responsibilities: str


class Step3ExperienceSchema(BaseModel):
    experience: List[ExperienceItemSchema]


# Step 4: Certifications
class CertificationItemSchema(BaseModel):
    certification_id: str  # UUID
    certification_name: str
    issuing_organization: str
    date_issued: str  # ISO date string
    expiration_date: Optional[str] = None  # ISO date string or null
    credential_id: Optional[str] = None


class Step4CertificationsSchema(BaseModel):
    certifications: List[CertificationItemSchema]


# Step 5: Expertise and Publications
class PublicationItemSchema(BaseModel):
    publication_id: str  # UUID
    title: str
    url: str


class Step5ExpertiseAndPublicationsSchema(BaseModel):
    expertise_topics: List[str]
    publications: List[PublicationItemSchema]


# Response Schema for GET all profile
class ContributorProfileResponseSchema(BaseModel):
    step1_basic_profile: Optional[dict] = None
    step2_education: List[dict] = []
    step3_experience: List[dict] = []
    step4_certifications: List[dict] = []
    step5_expertise_and_publications: Optional[dict] = None


# ==================== Article Schemas ====================

class CreateArticleSchema(BaseModel):
    title: str
    preview: str
    content: str
    image: str
    tags: List[str]
    categoryId: str


class UpdateArticleSchema(BaseModel):
    title: Optional[str] = None
    preview: Optional[str] = None
    content: Optional[str] = None
    image: Optional[str] = None
    tags: Optional[List[str]] = None
    categoryId: Optional[str] = None


# ==================== Partner Invitation Schemas ====================

class CreatePartnerInviteSchema(BaseModel):
    partner_email: EmailStr
    access_level: str = Field(default="latest_summary", description="'latest_summary' or 'full_history'")
    screening_types: List[str] = Field(
        default=["epds", "ppd", "hybrid"],
        description="List of screening types to share: 'epds', 'ppd', 'hybrid'"
    )
    
    @field_validator("access_level")
    @classmethod
    def validate_access_level(cls, v):
        if v not in ["latest_summary", "full_history"]:
            raise ValueError("access_level must be 'latest_summary' or 'full_history'")
        return v
    
    @field_validator("screening_types")
    @classmethod
    def validate_screening_types(cls, v):
        valid_types = ["epds", "ppd", "hybrid"]
        if not v or len(v) == 0:
            raise ValueError("At least one screening type must be specified")
        for st in v:
            if st not in valid_types:
                raise ValueError(f"Invalid screening type: {st}. Must be one of: {valid_types}")
        return v


class AcceptInviteSchema(BaseModel):
    invite_code: str = Field(..., min_length=6, max_length=10, description="Invite code received via email")


class PartnerInviteResponseSchema(BaseModel):
    invite_code: str
    partner_email: str
    expires_at: str
    created_at: str


class MotherPartnerLinkResponseSchema(BaseModel):
    link_id: str
    partner_id: str
    partner_name: str
    partner_email: str
    status: str
    permissions: dict
    created_at: str
    revoked_at: Optional[str] = None


class PartnerLinkedMotherSchema(BaseModel):
    link_id: str
    mother_id: str
    mother_name: str
    mother_email: str
    status: str
    permissions: dict
    created_at: str


class ScreeningSummarySchema(BaseModel):
    total_screenings: int
    epds_count: int
    ppd_count: int
    hybrid_count: int
    latest_epds: Optional[dict] = None
    latest_ppd: Optional[dict] = None
    latest_hybrid: Optional[dict] = None


class ScreeningHistoryItemSchema(BaseModel):
    id: str
    type: str  # "epds", "ppd", "hybrid"
    result: dict
    created_at: str
    recommended_articles: Optional[List["RecommendedArticleSchema"]] = Field(
        default=None,
        description="List of recommended articles (max 2 for result page)"
    )
    recommendations_status: Optional[str] = Field(
        default=None,
        description="Status of recommendation generation: 'ok' or 'unavailable'"
    )


class ScreeningHistoryResponseSchema(BaseModel):
    total: int
    items: List[ScreeningHistoryItemSchema]


# Additional response schemas for partner invitation endpoints

class CreateInviteResponseSchema(BaseModel):
    message: str
    invite_code: str
    expires_at: str


class AcceptInviteResponseSchema(BaseModel):
    message: str
    mother_id: Optional[str] = None
    mother_name: str
    is_verified: bool


class RevokeLinkResponseSchema(BaseModel):
    message: str
    link_id: str


# ==================== Additional Response Schemas ====================

class ScreeningCountResponseSchema(BaseModel):
    epds_screening_count: int
    ppd_risk_assessment_count: int
    hybrid_screening_count: int
    total_screening_count: int


class HybridScreeningResultResponseSchema(BaseModel):
    id: int
    risk_label: str
    final_probability: float
    is_critical: bool
    clinical_recommendation: str
    explanation: str
    fusion_method: str
    metrics: dict
    audit: dict
    epds_data: dict
    ppd_data: dict
    created_at: str
    system_disclaimer: str


class PPDRiskFormConfigResponseSchema(BaseModel):
    app_title: str
    description: str
    model_file: Optional[str] = None
    fields: List[dict]


class PPDHistoryItemSchema(BaseModel):
    id: str
    result: dict
    createdAt: str


class PPDHistoryResponseSchema(BaseModel):
    items: List[PPDHistoryItemSchema]


class PPDResultDetailSchema(BaseModel):
    id: str
    result: dict
    createdAt: str


class HybridScreeningSubmitResponseSchema(BaseModel):
    """
    Response schema for POST /screening/hybrid (immediate hybrid screening result).
    Matches the actual return structure from perform_hybrid_screening.
    """
    risk_label: str
    final_probability: float
    is_critical: bool
    clinical_recommendation: str
    explanation: str
    fusion_method: str
    metrics: dict
    audit: dict
    system_disclaimer: str
    recommended_articles: List["RecommendedArticleSchema"] = Field(
        default_factory=list,
        description="List of recommended articles based on this hybrid screening",
    )
    recommendations_status: str = Field(
        description="Status of recommendation generation: 'ok' or 'unavailable'",
    )
    risk_level_standard: Optional[str] = Field(
        default=None,
        description="Standardized hybrid risk level: LOW, MEDIUM, HIGH, or CRITICAL"
    )
    crisis_resources: Optional[List["CrisisResourceMiniOut"]] = Field(
        default=None,
        description="Recommended crisis resources (only included if include_crisis_resources=true in request)"
    )
    recommended_resource_ids: Optional[List[str]] = Field(
        default=None,
        description="IDs of recommended crisis resources stored in the database"
    )


class CreatePostResponseSchema(BaseModel):
    message: str
    id: str


class ViewPostListResponseSchema(BaseModel):
    items: List[ViewPostResponseSchema]


class ToggleLikeResponseSchema(BaseModel):
    id: str
    likeCount: int
    hasLiked: bool


class CreateCommentResponseSchema(BaseModel):
    message: str
    id: str


class ToggleCommentLikeResponseSchema(BaseModel):
    id: str
    likeCount: int
    hasLiked: bool


class UpdatePostResponseSchema(BaseModel):
    message: str
    id: str


class DeletePostResponseSchema(BaseModel):
    message: str
    id: str


class PostCountResponseSchema(BaseModel):
    total_posts: int


class UserPostsResponseSchema(BaseModel):
    items: List[ViewPostResponseSchema]


class CategoryListResponseSchema(BaseModel):
    items: List[CategoryResponseSchema]


class CreateCategoryResponseSchema(BaseModel):
    message: str
    id: str


class UploadImageResponseSchema(BaseModel):
    image_url: str


class CreateGroupResponseSchema(BaseModel):
    message: str
    id: str


class JoinGroupResponseSchema(BaseModel):
    message: str
    group_id: str


class UserGroupsResponseSchema(BaseModel):
    items: List[ViewGroupResponseSchema]


# ViewGroupPostListResponseSchema - Use List[ViewGroupPostResponseSchema] directly in response_model


class UpdateGroupResponseSchema(BaseModel):
    message: str
    id: str


class DeleteGroupResponseSchema(BaseModel):
    message: str
    id: str


class CreateGroupPostResponseSchema(BaseModel):
    message: str
    id: str


class UpdateGroupPostResponseSchema(BaseModel):
    message: str
    id: str


class DeleteGroupPostResponseSchema(BaseModel):
    message: str
    id: str


class CreateGroupCommentResponseSchema(BaseModel):
    message: str
    id: str


class ToggleGroupCommentLikeResponseSchema(BaseModel):
    id: str
    likeCount: int
    hasLiked: bool


class ContributorStepResponseSchema(BaseModel):
    message: str


class UploadArticleImageResponseSchema(BaseModel):
    image_url: str


class CreateArticleResponseSchema(BaseModel):
    message: str
    id: str
    title: str
    preview: str
    content: str
    image: str
    tags: List[str]
    category: dict
    status: str
    like_count: int
    created_at: str


class UpdateArticleResponseSchema(BaseModel):
    message: str
    id: str


class DeleteArticleResponseSchema(BaseModel):
    message: str
    id: str


# ArticleListResponseSchema - Use List[dict] directly in response_model


# ArticlePublishedListResponseSchema - Use List[dict] directly in response_model


class PublishArticleResponseSchema(BaseModel):
    message: str
    id: str


# ==================== General Response Schemas ====================

class MessageResponseSchema(BaseModel):
    message: str


class RootResponseSchema(BaseModel):
    message: str


class UserInfoSchema(BaseModel):
    id: int
    email: str
    name: str
    role: str


class SignupResponseSchema(BaseModel):
    message: str
    email: str
    access_token: str
    token_type: str
    user: UserInfoSchema
    firebase_token: Optional[str] = None


class LoginResponseSchema(BaseModel):
    message: str
    email: str
    name: str
    role: str
    access_token: str
    token_type: str
    user: UserInfoSchema
    firebase_token: Optional[str] = None


class ProfileResponseSchema(BaseModel):
    email: str
    name: str
    role: str


class PostCountResponseSchema(BaseModel):
    community_post_count: int
    group_post_count: int
    total_post_count: int


class ArticleStatsResponseSchema(BaseModel):
    total_article_count: int
    published_article_count: int
    pending_article_count: int
    total_like_count: int


class ToggleLikeResponseSchema(BaseModel):
    id: str
    likeCount: int
    hasLiked: bool


class UploadImageResponseSchema(BaseModel):
    message: str
    image_url: str


class CategoryItemSchema(BaseModel):
    id: str
    name: str


class CreateCategoryResponseSchema(BaseModel):
    message: str
    category: CategoryItemSchema


class CreatePostResponseSchema(BaseModel):
    message: str
    post_id: str


class CreateGroupResponseSchema(BaseModel):
    message: str
    group_id: str


class JoinGroupResponseSchema(BaseModel):
    message: str
    group_id: str


class CreateCommentResponseSchema(BaseModel):
    message: str
    comment_id: str


class ToggleCommentLikeResponseSchema(BaseModel):
    id: str
    likeCount: int
    hasLiked: bool


class EPDSResultItemSchema(BaseModel):
    id: str
    total_score: int
    risk_level: str
    created_at: str


class EPDSHistoryResponseSchema(BaseModel):
    history: List[EPDSResultItemSchema]
    count: int


class EPDSResultDetailSchema(BaseModel):
    """
    Detailed EPDS result as returned by GET /epds-screen/{result_id}.
    Matches the actual response shape used by the endpoint, where
    question scores are nested under an `answers` object.
    """
    id: int
    total_score: int
    risk_level: str
    answers: "EPDSAnswersSchema"
    created_at: str
    crisis_resources: Optional[List["CrisisResourceMiniOut"]] = None


class ScreeningCountResponseSchema(BaseModel):
    epds_screening_count: int
    ppd_risk_assessment_count: int
    hybrid_screening_count: int
    total_screening_count: int


class HybridScreeningAuditSchema(BaseModel):
    timestamp: str
    decision_path: List[str]
    is_discordant: bool
    uncertainty_flag: bool


class HybridScreeningHistoryItemSchema(BaseModel):
    id: str
    risk_label: str
    final_probability: float
    is_critical: bool
    clinical_recommendation: str
    epds_total_score: int
    epds_risk_level: str
    fusion_method: str
    explanation: str
    metrics: Dict[str, Any]
    audit: HybridScreeningAuditSchema
    created_at: str


class HybridScreeningHistoryResponseSchema(BaseModel):
    history: List[HybridScreeningHistoryItemSchema]
    count: int


class HybridScreeningResultResponseSchema(BaseModel):
    id: str
    epds_total: int
    ml_probability: float
    risk_label: str
    final_probability: float
    is_critical: bool
    explanation: str
    fusion_method: str
    created_at: str


class PPDHistoryItemSchema(BaseModel):
    id: str
    result: dict
    created_at: str


class PPDHistoryResponseSchema(BaseModel):
    results: List[PPDHistoryItemSchema]


class PPDResultDetailSchema(BaseModel):
    id: str
    result: dict
    created_at: str


class PPDRiskFormConfigResponseSchema(BaseModel):
    app_title: str
    description: str
    model_file: str
    fields: List[dict]


class EPDSAnswersSchema(BaseModel):
    q1: int
    q2: int
    q3: int
    q4: int
    q5: int
    q6: int
    q7: int
    q8: int
    q9: int
    q10: int


class EPDSResultDataSchema(BaseModel):
    id: int
    total_score: int
    risk_level: str
    answers: EPDSAnswersSchema
    created_at: str


class EPDSSubmitResponseSchema(BaseModel):
    message: str
    result: EPDSResultDataSchema
    interpretation: str
    recommended_articles: List["RecommendedArticleSchema"] = Field(
        default_factory=list,
        description="List of recommended articles based on this screening"
    )
    recommendations_status: str = Field(
        description="Status of recommendation generation: 'ok' or 'unavailable'"
    )
    risk_level_standard: Optional[str] = Field(
        default=None,
        description="Standardized risk level: LOW, MEDIUM, HIGH, or CRITICAL"
    )
    crisis_resources: Optional[List["CrisisResourceMiniOut"]] = Field(
        default=None,
        description="Recommended crisis resources (only included if include_crisis_resources=true in request)"
    )
    recommended_resource_ids: Optional[List[str]] = Field(
        default=None,
        description="IDs of recommended crisis resources stored in the database"
    )


class RecommendedArticleSchema(BaseModel):
    article_id: str
    title: str
    category: str
    risk_level: str
    external_url: str
    access_type: str
    score: float


class RecommendedArticlesDashboardResponseSchema(BaseModel):
    recommended_articles: List[RecommendedArticleSchema]
    source_screening_type: Optional[str] = None
    generated_at: Optional[str] = None
    status: Optional[str] = None


# ==================== Crisis Resources Schemas ====================

class CrisisContextSchema(BaseModel):
    """Reusable schema for crisis resource context in screening requests"""
    include_crisis_resources: bool = False
    city: Optional[str] = "Kathmandu"
    lat: Optional[float] = None
    lng: Optional[float] = None
    limit: int = Field(default=5, ge=1, le=10)


class CrisisResourceMiniOut(BaseModel):
    """Minimal output schema for crisis resource (embedded in screening responses)"""
    id: str
    name: str
    type: str
    city: Optional[str] = None
    address: Optional[str] = None
    phone: Optional[str] = None
    hotline: Optional[bool] = None
    website: Optional[str] = None
    hours: Optional[str] = None
    lat: Optional[float] = None
    lng: Optional[float] = None
    distance_km: Optional[float] = None


class CrisisResourceOut(BaseModel):
    """Output schema for crisis resource"""
    id: str
    name: str
    type: str
    province: Optional[str] = None
    city: str
    address: Optional[str] = None
    phone: Optional[str] = None
    hotline: bool
    website: Optional[str] = None
    hours: Optional[str] = None
    description: Optional[str] = None
    lat: Optional[float] = None
    lng: Optional[float] = None
    risk_supported: List[str]
    is_active: bool
    distance_km: Optional[float] = None


class CrisisResourceRecommendRequest(BaseModel):
    """Request schema for crisis resource recommendation"""
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    lat: Optional[float] = None
    lng: Optional[float] = None
    city: Optional[str] = None
    limit: Optional[int] = None

