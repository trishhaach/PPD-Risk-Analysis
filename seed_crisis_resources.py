"""
Seed script for Crisis Resources data.
Reads from data/crisis_resources_seed.json and inserts records into the database.
"""
import json
import os
from sqlmodel import Session
from database import engine
from models import CrisisResource


def normalize_type(type_str: str) -> str:
    """Normalize resource type from JSON to model values."""
    type_mapping = {
        "helpline": "helpline",
        "hospital": "hospital",
        "emergency": "emergency",
        "counseling center": "counseling",
        "community support": "community_support",
        "yoga & wellness": "wellness",
    }
    normalized = type_str.lower().strip()
    return type_mapping.get(normalized, normalized.replace(" ", "_").lower())


def seed():
    """Seed crisis resources from JSON file."""
    json_path = os.path.join(os.path.dirname(__file__), "data", "crisis_resources_seed.json")
    
    if not os.path.exists(json_path):
        print(f"Error: JSON file not found at {json_path}")
        return
    
    # Read JSON file
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading JSON file: {e}")
        return
    
    inserted_count = 0
    skipped_count = 0
    
    # Process each record
    with Session(engine) as session:
        for record in data:
            resource_id = record.get("id")
            
            # Check if ID already exists
            existing = session.get(CrisisResource, resource_id)
            if existing:
                skipped_count += 1
                print(f"Skipped: {resource_id} - {record.get('name', 'Unknown')} (already exists)")
                continue
            
            # Normalize type
            normalized_type = normalize_type(record.get("type", ""))
            
            # Create CrisisResource object
            # Handle risk_supported - default to empty list if not in JSON
            risk_supported = record.get("risk_supported", [])
            if not isinstance(risk_supported, list):
                risk_supported = []
            
            # Handle None values for lat/lng
            lat = record.get("lat")
            lng = record.get("lng")
            
            crisis_resource = CrisisResource(
                id=resource_id,
                name=record.get("name", ""),
                type=normalized_type,
                province=record.get("province"),
                city=record.get("city", ""),
                address=record.get("address"),
                phone=record.get("phone"),
                hotline=record.get("hotline", False),
                website=record.get("website"),
                hours=record.get("hours"),
                description=record.get("description"),
                lat=lat if lat is not None else None,
                lng=lng if lng is not None else None,
                risk_supported=risk_supported,
                is_active=True,  # Default to active
            )
            
            session.add(crisis_resource)
            inserted_count += 1
            print(f"Inserted: {resource_id} - {record.get('name', 'Unknown')}")
        
        # Commit all inserts
        try:
            session.commit()
            print("\n" + "="*50)
            print("Seeding Summary:")
            print(f"  Inserted: {inserted_count}")
            print(f"  Skipped:  {skipped_count}")
            print(f"  Total:    {len(data)}")
            print("="*50)
        except Exception as e:
            session.rollback()
            print(f"\nError committing to database: {e}")
            raise


if __name__ == "__main__":
    seed()

