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
        # Run migrations
        migrate_add_like_count_column()
        # Auto-migrate: Add any missing columns from models to database
        auto_migrate_model_schema()
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


def migrate_add_like_count_column():
    """Migration: Add like_count column to communitypost and grouppost tables if they don't exist"""
    try:
        from sqlalchemy import text, inspect
        inspector = inspect(engine)
        
        # Migrate communitypost table
        try:
            columns = [col['name'] for col in inspector.get_columns('communitypost')]
            if 'like_count' not in columns:
                with Session(engine) as session:
                    session.execute(text(
                        "ALTER TABLE communitypost ADD COLUMN like_count INTEGER NOT NULL DEFAULT 0"
                    ))
                    session.commit()
                    logger.info("Successfully added like_count column to communitypost table")
                    print("[OK] Added like_count column to communitypost table")
            else:
                logger.info("like_count column already exists in communitypost table")
                print("[OK] like_count column already exists in communitypost")
        except Exception as e:
            logger.error(f"Failed to add like_count column to communitypost: {e}")
            print(f"Warning: Could not add like_count column to communitypost: {e}")
        
        # Migrate grouppost table
        try:
            columns = [col['name'] for col in inspector.get_columns('grouppost')]
            if 'like_count' not in columns:
                with Session(engine) as session:
                    session.execute(text(
                        "ALTER TABLE grouppost ADD COLUMN like_count INTEGER NOT NULL DEFAULT 0"
                    ))
                    session.commit()
                    logger.info("Successfully added like_count column to grouppost table")
                    print("[OK] Added like_count column to grouppost table")
            else:
                logger.info("like_count column already exists in grouppost table")
                print("[OK] like_count column already exists in grouppost")
        except Exception as e:
            logger.error(f"Failed to add like_count column to grouppost: {e}")
            print(f"Warning: Could not add like_count column to grouppost: {e}")
    except Exception as e:
        logger.error(f"Failed to run like_count migration: {e}")
        print(f"Warning: Could not run like_count migration: {e}")


def auto_migrate_model_schema():
    """
    Auto-migration: Compare SQLModel definitions with database schema and add missing columns.
    This helps prevent schema mismatch issues.
    
    NOTE: This only adds columns. For more complex migrations (renames, deletes, type changes),
    use a proper migration tool like Alembic.
    """
    try:
        from sqlalchemy import text, inspect
        import models
        inspector = inspect(engine)
        
        # Get all tables from SQLModel metadata instead of registry
        all_tables = SQLModel.metadata.tables
        migrations_applied = []
        
        for table_name, table in all_tables.items():
            
            # Get model columns with their definitions
            model_columns = {}
            for col in table.columns:
                model_columns[col.name] = col
            
            # Get database columns
            try:
                db_columns = {col['name']: col for col in inspector.get_columns(table_name)}
            except Exception as e:
                # Table doesn't exist yet - create_all will handle it, or table doesn't exist in DB
                logger.debug(f"Table {table_name} not found in database, skipping: {e}")
                continue
            
            # Find missing columns
            missing_columns = set(model_columns.keys()) - set(db_columns.keys())
            
            for col_name in missing_columns:
                col_def = model_columns[col_name]
                
                # Build ALTER TABLE statement
                # Get column type
                col_type = str(col_def.type)
                nullable = "NULL" if col_def.nullable else "NOT NULL"
                default = ""
                
                if col_def.default is not None:
                    if hasattr(col_def.default, 'arg'):
                        default_val = col_def.default.arg
                        if isinstance(default_val, (int, float)):
                            default = f"DEFAULT {default_val}"
                        elif isinstance(default_val, str):
                            default = f"DEFAULT '{default_val}'"
                    elif col_def.default is None and col_def.nullable:
                        default = "DEFAULT NULL"
                
                try:
                    with Session(engine) as session:
                        alter_sql = f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_type} {nullable} {default}".strip()
                        session.execute(text(alter_sql))
                        session.commit()
                        migrations_applied.append(f"{table_name}.{col_name}")
                        logger.info(f"Added missing column {col_name} to table {table_name}")
                        print(f"[OK] Added column {col_name} to {table_name}")
                except Exception as e:
                    logger.error(f"Failed to add column {col_name} to {table_name}: {e}")
                    print(f"Warning: Could not add column {col_name} to {table_name}: {e}")
        
        if migrations_applied:
            logger.info(f"Auto-migration applied {len(migrations_applied)} column(s): {', '.join(migrations_applied)}")
        else:
            logger.debug("No auto-migrations needed")
            
    except Exception as e:
        logger.error(f"Failed to run auto-migration: {e}")
        print(f"Warning: Could not run auto-migration: {e}")
