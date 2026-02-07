"""
Service for fetching recommended crisis resources based on risk level and location.
"""
from typing import List, Optional
from sqlmodel import Session
from models import CrisisResource
from crisis_resources import risk_to_allowed_types, haversine_distance
from schemas import CrisisResourceMiniOut


def get_recommended_crisis_resources(
    session: Session,
    risk_level: str,
    city: str,
    lat: Optional[float],
    lng: Optional[float],
    limit: int
) -> List[CrisisResourceMiniOut]:
    """
    Get recommended crisis resources based on risk level, city, and location.
    
    Uses the same rules as /crisis-resources/recommend endpoint:
    - Allowed resource types by risk:
        LOW => ["wellness"]
        MEDIUM => ["counseling", "wellness"]
        HIGH/CRITICAL => ["hospital", "counseling", "helpline", "emergency"]
    - Filters: is_active=true, city match (case-insensitive), type in allowed types,
      and risk_level must be present in risk_supported array
    - If no results for requested city, fallback to Kathmandu
    - If lat/lng provided, compute distance (haversine) and sort by distance;
      otherwise sort hotlines first then name
    - Cap limit to max 10
    
    Args:
        session: SQLModel database session
        risk_level: Standardized risk level ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        city: City to search in
        lat: User's latitude (optional)
        lng: User's longitude (optional)
        limit: Maximum number of results (will be capped at 10)
    
    Returns:
        List of CrisisResourceMiniOut objects
    """
    # Cap limit to max 10
    limit = min(limit, 10)
    
    # Get allowed types for risk level
    allowed_types = risk_to_allowed_types(risk_level)
    if not allowed_types:
        return []
    
    # Normalize risk level for array matching
    risk_level_upper = risk_level.upper().strip()
    
    # Build query
    query = session.query(CrisisResource).filter(
        CrisisResource.is_active == True,
        CrisisResource.type.in_(allowed_types)
    )
    
    # Filter by city (case-insensitive)
    city_filter = CrisisResource.city.ilike(f"%{city}%")
    query = query.filter(city_filter)
    
    # Filter by risk_supported array containing the risk level
    query = query.filter(
        CrisisResource.risk_supported.contains([risk_level_upper])
    )
    
    # Execute query
    resources = query.all()
    
    # If no results for the city, fallback to Kathmandu
    if not resources and city.lower() != "kathmandu":
        query = session.query(CrisisResource).filter(
            CrisisResource.is_active == True,
            CrisisResource.type.in_(allowed_types),
            CrisisResource.city.ilike("%Kathmandu%")
        )
        query = query.filter(
            CrisisResource.risk_supported.contains([risk_level_upper])
        )
        resources = query.all()
    
    # Calculate distances and prepare results
    results = []
    for resource in resources:
        distance_km = None
        if lat is not None and lng is not None:
            distance_km = haversine_distance(
                lat,
                lng,
                resource.lat,
                resource.lng
            )
        
        results.append(CrisisResourceMiniOut(
            id=resource.id,
            name=resource.name,
            type=resource.type,
            city=resource.city,
            address=resource.address,
            phone=resource.phone,
            hotline=resource.hotline,
            website=resource.website,
            hours=resource.hours,
            lat=resource.lat,
            lng=resource.lng,
            distance_km=distance_km
        ))
    
    # Sort results
    if lat is not None and lng is not None:
        # Sort by distance (None distances at the end)
        results.sort(key=lambda x: (x.distance_km is None, x.distance_km or float('inf')))
    else:
        # Sort by hotline (desc) then name (asc)
        results.sort(key=lambda x: (-x.hotline, x.name))
    
    # Return top limit
    return results[:limit]

