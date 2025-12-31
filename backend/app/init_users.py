from app.database import init_db, add_user

if __name__ == "__main__":
    print("Initializing users database...")
    init_db()
    
    # Add default user: trev/trev
    add_user("admin", "admin123")
    
    print("Database initialized successfully") 
