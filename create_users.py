from werkzeug.security import generate_password_hash
from main import db, User

# Create users for different departments
def create_users():
    users = [
        {'username': 'finance_user', 'password': 'finance_pass', 'role': 'User', 'department': 'Finance'},
        {'username': 'hr_user', 'password': 'hr_pass', 'role': 'User', 'department': 'HR'},
        {'username': 'sales_user', 'password': 'sales_pass', 'role': 'User', 'department': 'Sales'},
        {'username': 'ict_admin', 'password': 'admin_pass', 'role': 'ICT Admin', 'department': 'ICT'}
    ]

    for user_data in users:
        if not User.query.filter_by(username=user_data['username']).first():
            hashed_password = generate_password_hash(user_data['password'], method='pbkdf2:sha256')
            new_user = User(username=user_data['username'], password=hashed_password, role=user_data['role'], department=user_data['department'])
            db.session.add(new_user)
            db.session.commit()
            print(f"Added user {user_data['username']}")

if __name__ == '__main__':
    from main import app
    with app.app_context():
        db.create_all()
        create_users()



