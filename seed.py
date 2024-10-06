from app import app, db
from models import User, Student, Unit, School, Event, Report, PaymentReminder, AgeTransitionNotification, Payment
from datetime import date
import random

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
        User(name="John Doe", email="john@example.com", phone_number="0712345678", role="admin"),
        User(name="Jane Smith", email="jane@example.com", phone_number="0723456789", role="guide"),
        User(name="Bob Johnson", email="bob@example.com", phone_number="0734567890", role="guide")
    ]
    
    # Set passwords
    users[0].password_hash = "password123"
    users[1].password_hash = "password456"
    users[2].password_hash = "password789"
    db.session.add_all(users)
    print("Users Created Successfully")
    db.session.commit()

    # Create Units
    units = [
        Unit(unit_name="Brownies", min_age=7, max_age=10, guide_id=2),
        Unit(unit_name="Guides", min_age=11, max_age=14, guide_id=2),
        Unit(unit_name="Rangers", min_age=15, max_age=18, guide_id=3)
    ]
    db.session.add_all(units)
    print("Units Created Successfully")
    db.session.commit()

    # Create Schools
    schools = [
        School(school_name="Nairobi Primary", county="Nairobi", headteacher_name="Mr. Kamau", school_type="Public", registration_date=date(2020, 1, 15), guide_id=2),
        School(school_name="Mombasa Academy", county="Mombasa", headteacher_name="Mrs. Ochieng", school_type="Private", registration_date=date(2019, 9, 1), guide_id=3)
    ]
    db.session.add_all(schools)
    print("Schools Created Successfully")
    db.session.commit()

    # Create Students
    students = []
    for i in range(50):
        age = random.randint(7, 18)
        unit_id = 1 if age <= 10 else (2 if age <= 14 else 3)
        students.append(Student(
            name=f"Student {i+1}",
            age=age,
            unit_id=unit_id,
            school_id=random.choice([1, 2]),
            guide_leader_id=random.choice([2, 3]),
            membership_status=random.choice(["active", "inactive", "pending"])
        ))
    db.session.add_all(students)
    print("Students Created Successfully")
    db.session.commit()

    # Create Events
    events = [
        Event(event_name="Annual Camp", event_date=date(2024, 7, 15), event_type="camp", school_id=1),
        Event(event_name="Leadership Training", event_date=date(2024, 8, 20), event_type="training", school_id=2),
        Event(event_name="Community Service", event_date=date(2024, 9, 5), event_type="service", school_id=1)
    ]
    db.session.add_all(events)
    print("Events Created Successfully")
    db.session.commit()

    # Create Reports
    reports = [
        Report(school_id=1, unit_id=1, total_membership_fees_collected=15000, report_date=date(2024, 6, 30), report_type="quarterly"),
        Report(school_id=2, unit_id=2, total_membership_fees_collected=18000, report_date=date(2024, 6, 30), report_type="quarterly"),
        Report(school_id=1, unit_id=3, total_membership_fees_collected=12000, report_date=date(2024, 6, 30), report_type="quarterly")
    ]
    db.session.add_all(reports)
    print("Reports Created Successfully")
    db.session.commit()

    # Create Payment Reminders
    reminders = []
    for student in students:
        if random.choice([True, False]):
            reminders.append(PaymentReminder(
                student_id=student.id,
                reminder_date=date(2024, random.randint(1, 12), random.randint(1, 28)),
                reminder_type=random.choice(["email", "sms"]),
                status=random.choice(["sent", "pending"])
            ))
    db.session.add_all(reminders)
    print("Reminders Created Successfully")
    db.session.commit()

    # Create Age Transition Notifications
    transitions = []
    for student in students:
        if student.age in [10, 14]:
            from_unit = "Brownies" if student.age == 10 else "Guides"
            to_unit = "Guides" if student.age == 10 else "Rangers"
            transitions.append(AgeTransitionNotification(
                student_id=student.id,
                from_unit=from_unit,
                to_unit=to_unit,
                notification_date=date(2024, random.randint(1, 12), random.randint(1, 28)),
                status=random.choice(["pending", "sent"])
            ))
    db.session.add_all(transitions)
    print("Transitions Created Successfully")
    db.session.commit()

    # Create Payments
    payments = []
    for _ in range(20):  # Create 20 payments
        amount = random.choice([1000, 1500, 2000, 2500])
        payment_date = date(2024, random.randint(1, 12), random.randint(1, 28))
        
        # Randomly choose to associate payment with a user or a school
        if random.choice([True, False]):  # 50% chance for user or school
            payment = Payment(
                amount=amount,
                payment_date=payment_date,
                user_id=random.choice([1, 2, 3]),  # Choose a user randomly
                school_id=None  # No school association
            )
        else:
            payment = Payment(
                amount=amount,
                payment_date=payment_date,
                user_id=None,  # No user association
                school_id=random.choice([1, 2])  # Choose a school randomly
            )
        payments.append(payment)

    db.session.add_all(payments)
    print("Payments Created Successfully")
    db.session.commit()

    print("Database seeded successfully!")

if __name__ == "__main__":
    with app.app_context():
        seed_database()
