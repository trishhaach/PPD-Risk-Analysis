from sqlmodel import SQLModel, create_engine
import logging

logger = logging.getLogger(__name__)

DATABASE_URL = "postgresql://postgres.brirytbelvtylkljscgv:FIRSTDECEMBER2002@aws-1-us-east-1.pooler.supabase.com:5432/postgres"
engine = create_engine(DATABASE_URL, echo=False)

def init_db():
    try:
        import models  
        SQLModel.metadata.create_all(engine)
        print("Database initialized!")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        print(f"Warning: Database initialization failed: {e}")
        print("The application will continue but database operations may fail.")
