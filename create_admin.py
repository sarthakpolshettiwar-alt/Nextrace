import os
import sys
from werkzeug.security import generate_password_hash
from database import setup_database, create_user, get_user_by_username

def create_admin_user():
    setup_database()
    
    username = "admin"
    email = "admin@example.com"
    password = "Password123!"
    
    if get_user_by_username(username):
        print(f"User '{username}' already exists.")
        return
        
    pwd_hash = generate_password_hash(password)
    user_id = create_user(username, email, pwd_hash, is_verified=True)
    
    print(f"Admin user created successfully!")
    print(f"ID: {user_id}")
    print(f"Username: {username}")
    print(f"Email: {email}")
    print(f"Password: {password}")

if __name__ == "__main__":
    create_admin_user()
