from application.main import db
from flask import current_app
from flask_login import UserMixin


class Account(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    member = db.Column(db.Boolean, default=False)


class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), unique=True)
    submitter = db.Column(db.String(100))
    credit = db.Column(db.String(100))
    mg_model = db.Column(db.String(100))


def migrate_db():
    db.create_all()
    db.session.add(Account(username=current_app.config['ADMIN_USERNAME'],
                           password=current_app.config['ADMIN_PASSWORD'],
                           first_name="root", last_name="root", member=True))
    db.session.add(Account(username="solidsnake@protonmail.com",
                           password="2001_$pace_Odyssey",
                           first_name="Iroquois", last_name="Pliskin", member=True))
    db.session.add(Image(id=1, filename="b6116d5a-a415-4438-8f43-2b4cb648593e.png",
                         submitter="solidsnake@protonmail.com", credit="N/A", mg_model="NULL"))
    db.session.add(Image(id=2, filename="3f9148b5-22da-48e8-b36e-fa9a2c723b81.png",
                         submitter="solidsnake@protonmail.com",
                         credit="flag{m4ss_4ssignm3nt_b4d}", mg_model="FLAG_IMAGE"))
    db.session.commit()
