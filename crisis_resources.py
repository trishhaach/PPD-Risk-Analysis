"""
Helper functions for crisis resources recommendation logic.
"""
import math
from typing import List, Optional


def risk_to_allowed_types(risk_level: str) -> List[str]:
    """
    Map risk level to allowed resource types.
    
    Args:
        risk_level: One of "LOW", "MEDIUM", "HIGH", "CRITICAL"
    
    Returns:
        List of allowed resource types
    """
    risk_level_upper = risk_level.upper().strip()
    
    mapping = {
        "LOW": ["wellness"],
        "MEDIUM": ["counseling", "wellness"],
        "HIGH": ["hospital", "counseling", "helpline", "emergency"],
        "CRITICAL": ["hospital", "counseling", "helpline", "emergency"],
    }
    
    return mapping.get(risk_level_upper, [])


def haversine_distance(
    user_lat: float,
    user_lng: float,
    res_lat: Optional[float],
    res_lng: Optional[float]
) -> Optional[float]:
    """
    Calculate the distance between two points on Earth using the Haversine formula.
    
    Args:
        user_lat: User's latitude
        user_lng: User's longitude
        res_lat: Resource latitude (can be None)
        res_lng: Resource longitude (can be None)
    
    Returns:
        Distance in kilometers, or None if resource coordinates are missing
    """
    if res_lat is None or res_lng is None:
        return None
    
    # Earth's radius in kilometers
    R = 6371.0
    
    # Convert latitude and longitude from degrees to radians
    lat1_rad = math.radians(user_lat)
    lat2_rad = math.radians(res_lat)
    delta_lat = math.radians(res_lat - user_lat)
    delta_lng = math.radians(res_lng - user_lng)
    
    # Haversine formula
    a = (
        math.sin(delta_lat / 2) ** 2
        + math.cos(lat1_rad)
        * math.cos(lat2_rad)
        * math.sin(delta_lng / 2) ** 2
    )
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    
    # Distance in kilometers
    distance = R * c
    
    return distance

