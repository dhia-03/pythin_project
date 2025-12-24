"""
Test script to create test users for each role
Run this to quickly set up test accounts for RBAC testing
"""
from database.db_manager import db

def create_test_users():
    print("[*] Creating test users for RBAC testing...")
    
    # Create analyst user
    user, error = db.create_user('analyst', 'analyst123', 'analyst', 'analyst@ids.com')
    if user:
        print("[+] Created analyst user: analyst / analyst123")
    elif error and "already exists" not in error:
        print(f"[-] Error creating analyst: {error}")
    
    # Create viewer user
    user, error = db.create_user('viewer', 'viewer123', 'viewer', 'viewer@ids.com')
    if user:
        print("[+] Created viewer user: viewer / viewer123")
    elif error and "already exists" not in error:
        print(f"[-] Error creating viewer: {error}")
    
    print("\n[✓] Test users created!")
    print("\nYou can now test with:")
    print("  Admin:   admin / admin123")
    print("  Analyst: analyst / analyst123")  
    print("  Viewer:  viewer / viewer123")

if __name__ == '__main__':
    create_test_users()
