from app import app, db
from models import User, Student, Youth, School, Payment
from datetime import datetime, timedelta
import random

def seed_database():
    try:
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
            User(name="John Doe", email="john@example.com", phone_number="0717370359", roles="admin", membership_no =123),
            User(name="Jane Smith", email="jane@example.com", phone_number="0717370359", roles="finance", membership_no =235),
            User(name="Samuel Kim", email="samuel@example.com", phone_number="0717370359", roles="admin", membership_no =878),
            User(name="Alice Wambui", email="alice@example.com", phone_number="0717370359", roles="finance", membership_no =845),
        ]

        # Set hashed passwords
        pwd = '123'
        for user in users:
            user.password_hash = pwd

        # Add users to the session and commit
        db.session.add_all(users)
        db.session.commit()
        print("Users Created Successfully")

        # Create Youths with registration fee and yearly payment
        youths = [
            Youth(name="Young Adult 1", email="laurachepck@gmail.com", phone_number="0717370359", dob=datetime(2000, 1, 1), registration_fee=500, roles="SuperYouth", membership_no =597),
            Youth(name="Young Adult 2", email="jonniekaras@gmail.com", phone_number="0717370359", dob=datetime(1998, 6, 12), registration_fee=500,roles="SuperYouth", membership_no =584),
            Youth(name="Young Adult 3", email="adult3@example.com", phone_number="0717370359", dob=datetime(1980, 7, 20), registration_fee=500,membership_no =587),
            Youth(name="Young Adult 1", email="adult1@example.com", phone_number="0717370359", dob=datetime(2000, 1, 1), registration_fee=500, membership_no =594),
        ]

        # Set hashed passwords for youths
        pwd = '123'
        for youth in youths:
            youth.password_hash = pwd

        # Add youths to the session and commit
        db.session.add_all(youths)
        db.session.commit()
        print("Youths Created Successfully")

        # Create Schools with guide_leader_id and password_hash
        schools = [
            School(school_name="Green Valley High School", email="green@example.com", phone_number="0717370359", county="Nairobi", headteacher_name="Mr. Smith", school_type="Public", guide_leader_id=1, membership_no =246),
            School(school_name="Sunnydale Academy", email="sunnydale@example.com", phone_number="0717370359", county="Nairobi", headteacher_name="Mrs. Johnson", school_type="Private", guide_leader_id=2, membership_no =319),
        ]
        pwd = '123'
        for school in schools:
            school.password_hash = pwd

        # Add schools to the session and commit
        db.session.add_all(schools)
        db.session.commit()
        print("Schools Created Successfully")

        # Create Students
        students = [
            Student(name="Kenyan Boy", dob=datetime(2010, 5, 15), category="rainbows", school_id=1, parentName='John Wambua', parentPhone='0717070707', membership_no =5452),
            Student(name="Kenyan Girl", dob=datetime(2008, 3, 10), category="brownies", school_id=1, parentName='John Wambua', parentPhone='0717070707', membership_no =8455),
            Student(name="International Student", dob=datetime(2004, 8, 21), category="girl_guides", school_id=2, parentName='John Wambua', parentPhone='0717070707', membership_no =8564),
            Student(name="Young Scout", dob=datetime(2001, 1, 5), category="rangers", school_id=2, parentName='John Wambua', parentPhone='0717070707', membership_no =5512),
        ]

        # Add students to the session and commit
        db.session.add_all(students)
        db.session.commit()
        print("Students Created Successfully")

        # Create Payments with randomized payment dates
        payments = []
        base_date = datetime.now()

        for _ in range(24):
            # Decide whether to associate with youth or school, ensuring one is always None
            if random.choice([True, False]):
                random_youth_id = random.randint(1, len(youths))  # Associate with a youth
                random_school_id = None
            else:
                random_youth_id = None
                random_school_id = random.randint(1, len(schools))  # Associate with a school

            payment_date = base_date - timedelta(days=random.randint(1, 365))
            
            # Create a Payment instance, ensuring values match model validations
            payment = Payment(
                school_id=random_school_id,
                youth_id=random_youth_id,
                amount=random.choice([500, 500, 500, 500]),
                status="completed",
                payment_date=payment_date,
                payment_method=random.choice(["bank transfer", "mobile money"]),
                payment_type=random.choice(["registration", "yearly"])  # Ensure valid types
            )
            payments.append(payment)

        # Add payments to the session and commit
        db.session.add_all(payments)
        db.session.commit()
        print("Payments Created successfully!")
        print("Database seeded successfully!")
    except Exception as e:
        print(f"An error occurred while seeding the database: {e}")

if __name__ == "__main__":
    with app.app_context():
        seed_database()
