import os
import sys

# Add the parent directory to the path so we can import the app
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app, db
from app.models.task import TaskLock

def main():
    app = create_app()
    with app.app_context():
        try:
            num_deleted = db.session.query(TaskLock).delete()
            db.session.commit()
            print(f"Successfully deleted {num_deleted} lock(s) from the TaskLock table.")
        except Exception as e:
            db.session.rollback()
            print(f"Error deleting locks: {str(e)}")

if __name__ == "__main__":
    main()
