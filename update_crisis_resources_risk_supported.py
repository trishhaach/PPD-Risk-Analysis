"""
Update existing crisis resources to populate risk_supported based on their type.
This script updates records that have empty risk_supported arrays.
"""
from sqlmodel import Session
from database import engine
from models import CrisisResource


def get_risk_supported_for_type(resource_type: str) -> list:
    """
    Determine risk_supported values based on resource type.
    
    Args:
        resource_type: Normalized resource type (helpline, hospital, emergency, counseling, wellness, etc.)
    
    Returns:
        List of risk levels this resource type supports
    """
    type_to_risks = {
        "wellness": ["LOW"],
        "counseling": ["MEDIUM", "HIGH", "CRITICAL"],
        "helpline": ["HIGH", "CRITICAL"],
        "hospital": ["HIGH", "CRITICAL"],
        "emergency": ["CRITICAL"],
        "community_support": ["LOW", "MEDIUM"],
    }
    
    # Default: if type not found, support all risk levels
    return type_to_risks.get(resource_type, ["LOW", "MEDIUM", "HIGH", "CRITICAL"])


def update_risk_supported():
    """Update existing crisis resources with risk_supported values based on their type."""
    updated_count = 0
    
    with Session(engine) as session:
        # Get all crisis resources
        resources = session.query(CrisisResource).all()
        
        for resource in resources:
            # Check if risk_supported is empty or None
            if not resource.risk_supported or len(resource.risk_supported) == 0:
                # Populate based on type
                risk_supported = get_risk_supported_for_type(resource.type)
                resource.risk_supported = risk_supported
                updated_count += 1
                print(f"Updated: {resource.id} - {resource.name} - Type: {resource.type} - Risk: {risk_supported}")
        
        # Commit all updates
        try:
            session.commit()
            print("\n" + "="*50)
            print("Update Summary:")
            print(f"  Updated: {updated_count} resources")
            print(f"  Total:   {len(resources)} resources")
            print("="*50)
        except Exception as e:
            session.rollback()
            print(f"\nError committing to database: {e}")
            raise


if __name__ == "__main__":
    update_risk_supported()

