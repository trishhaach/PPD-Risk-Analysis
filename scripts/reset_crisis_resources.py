"""
Script to truncate the crisis_resources table.
USE WITH CAUTION: This deletes all crisis resource data.
"""
from sqlmodel import Session, text
from database import engine

def reset_table():
    print("Truncating crisis_resources table...")
    with Session(engine) as session:
        try:
            # CASCADE ensures constraints are handled if any exist (though rare for this table)
            session.exec(text("TRUNCATE TABLE crisisresource CASCADE"))
            session.commit()
            print("Successfully truncated crisis_resources table.")
        except Exception as e:
            session.rollback()
            print(f"Error truncating table: {e}")

if __name__ == "__main__":
    reset_table()
