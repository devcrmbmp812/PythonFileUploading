from webapp import bcrypt, UserMixin, db


class User(UserMixin, db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True)
    password = db.Column(db.String)
    role = db.Column(db.String)

    def __init__(self, username, password, role):
        self.username = username
        self.password = bcrypt.generate_password_hash(password)
        if role == None:
            self.role = "None"
        else:
            self.role = role
