from sqlmodel import SQLModel, create_engine, Session
import logging

logger = logging.getLogger(__name__)

DATABASE_URL = "postgresql://postgres.brirytbelvtylkljscgv:FIRSTDECEMBER2002@aws-1-us-east-1.pooler.supabase.com:5432/postgres"
engine = create_engine(DATABASE_URL, echo=False)

def init_db():
    try:
        import models  
        SQLModel.metadata.create_all(engine)
        print("Database initialized!")
        # Seed default categories if they don't exist
        seed_default_categories()
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        print(f"Warning: Database initialization failed: {e}")
        print("The application will continue but database operations may fail.")


def seed_default_categories():
    """Seed default categories for community posts"""
    try:
        from models import Category
        with Session(engine) as session:
            # Check if categories already exist
            existing = session.query(Category).count()
            if existing > 0:
                logger.info("Categories already exist, skipping seed")
                return
            
            # Create default categories
            categories = [
                Category(name="Discussion"),
                Category(name="Research")
            ]
            
            for category in categories:
                session.add(category)
            
            session.commit()
            logger.info("Default categories seeded successfully")
            print("Default categories (Discussion, Research) created!")
    except Exception as e:
        logger.error(f"Failed to seed default categories: {e}")
        print(f"Warning: Could not seed default categories: {e}")
