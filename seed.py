from app import app, db
from models import User, Student, Youth, School, Payment, Event
from datetime import datetime

def seed_database():
    print("Seeding database...")

    # Clear existing data
    print("DELETING THE CURRENT DATABASE")
    db.drop_all()
    print("DELETED THE CURRENT DATABASE")
    print(".......")
    print("CREATING A NEW DB")
    db.create_all()
    print("New DB CREATED")

    # Create Users
    users = [
        User(name="John Doe", email="john@example.com", phone_number="0712345678", roles="admin"),
        User(name="Jane Smith", email="jane@example.com", phone_number="0712345679", roles="finance"),
        User(name="Samuel Kim", email="samuel@example.com", phone_number="0712345680", roles="admin"),
        User(name="Alice Wambui", email="alice@example.com", phone_number="0712345681", roles="finance"),
    ]
    
    # Set passwords
    users[0].password_hash = "password123"
    users[1].password_hash = "password456"
    users[2].password_hash = "password789"
    users[3].password_hash = "password789"
    
    # Add users to the session and commit
    db.session.add_all(users)
    db.session.commit()
    print("Users Created Successfully")
# Create Youths with registration fee and yearly payment
    youths = [
        Youth(name="Young Adult 1", email="adult1@example.com", phone_number="0712345678", dob=datetime(2000, 1, 1), registration_fee=500, yearly_payment=500, roles="SuperYouth"),
        Youth(name="Young Adult 2", email="adult2@example.com", phone_number="0712345678", dob=datetime(1998, 6, 12), registration_fee=500, yearly_payment=500),
        Youth(name="Young Adult 3", email="adult3@example.com", phone_number="0712345678", dob=datetime(1980, 7, 20), registration_fee=500, yearly_payment=500),
    ]
    
    # Set passwords for youths
    youths[0].password_hash = "password789"
    youths[1].password_hash = "password456"
    youths[2].password_hash = "password789"
    
    # Add youths to the session and commit
    db.session.add_all(youths)
    db.session.commit()
    print("Youths Created Successfully")
    # Create Schools with guide_leader_id and password_hash
    schools = [
        School(school_name="Green Valley High School", email="green@example.com", phone_number="0712345678", county="Nairobi", headteacher_name="Mr. Smith", school_type="Public", guide_leader_id=1),
        School(school_name="Sunnydale Academy", email="sunnydale@example.com", phone_number="0712345678", county="Nairobi", headteacher_name="Mrs. Johnson", school_type="Private", guide_leader_id=2),
    ]
    schools[0].password_hash = "password123"
    schools[1].password_hash = "password456"
    
    # Add schools to the session and commit
    db.session.add_all(schools)
    db.session.commit()
    print("Schools Created Successfully")

    # Create Students
    students = [
        Student(name="Kenyan Boy", dob=datetime(2010, 5, 15), category="rainbows", school_id=1, parentName='John Wambua', parentPhone='0717070707'),
        Student(name="Kenyan Girl", dob=datetime(2008, 3, 10), category="brownies", school_id=1,parentName='John Wambua', parentPhone='0717070707'),
        Student(name="International Student", dob=datetime(2004, 8, 21), category="girl_guides", school_id=2, parentName='John Wambua', parentPhone='0717070707'),
        Student(name="Young Scout", dob=datetime(2001, 1, 5), category="rangers", school_id=2, parentName='John Wambua', parentPhone='0717070707'),
    ]
    
    # Add students to the session and commit
    db.session.add_all(students)
    db.session.commit()
    print("Students Created Successfully")

    

    # Create Payments for the youths
    payments = [
        Payment(school_id=None, youth_id=1, amount=1000, status="completed", payment_date=datetime.now(), payment_method="bank transfer"),  # Payment for Young Adult 1
        Payment(school_id=1, youth_id=None, amount=10000, status="completed", payment_date=datetime.now(), payment_method="mobile money"),  # Yearly payment for Young Adult 1
        Payment(school_id=None, youth_id=2, amount=500, status="completed", payment_date=datetime.now(), payment_method="bank transfer"),  # Payment for Young Adult 2
        Payment(school_id=1, youth_id=None, amount=20500, status="completed", payment_date=datetime.now(), payment_method="mobile money"),  # Yearly payment for Young Adult 2
        Payment(school_id=None, youth_id=2, amount=500, status="completed", payment_date=datetime.now(), payment_method="bank transfer"),  # Payment for Young Adult 3
        Payment(school_id=2, youth_id=None, amount=10500, status="completed", payment_date=datetime.now(), payment_method="mobile money"),  # Yearly payment for Young Adult 3
    ]
    
    # Add payments to the session and commit
    db.session.add_all(payments)
    db.session.commit()
    print("Payments Created Successfully")

    print("Database seeded successfully!")

if __name__ == "__main__":
    with app.app_context():
        seed_database()
