from flask.ext.login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from database import db

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    token = db.Column(db.String(64))
    role = db.Column(db.String(64)) # admin, user
    temp_password = db.Column(db.Boolean())

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User %r>\n' % self.username
class TraceFile(db.Model):
    __tablename__ = 'tracefiles'

    id = db.Column(db.String(8), primary_key=True)
    name = db.Column(db.String(128), index=True)
    description = db.Column(db.Text())
    filename = db.Column(db.String(128))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    username = db.relationship('User')
    filesize = db.Column(db.Integer) #Bytes
    filetype = db.Column(db.String(64))
    packet_count = db.Column(db.Integer)
    date_added = db.Column(db.DateTime)

    def __repr__(self):
        return '<TraceFile %r, filename: %r>\n' % (self.name, self.filename)

class Tag(db.Model):
    __tablename__ = 'tags'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    file_id = db.Column(db.String(8), db.ForeignKey('tracefiles.id'))

    def __repr__(self):
        return '<Tag %r, file_id: %s>\n' % (self.name, self.file_id)

class Log(db.Model):
    __tablename__ = 'logs'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime)
    level = db.Column(db.String) #info, warning, error
    description = db.Column(db.String)

    def __repr__(self):
        return '<Log: %s - %s - %s>\n' % (self.timestamp, self.level, self.description)

class Template(db.Model):
    __tablename__ = 'templates'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    command = db.Column(db.String(100))
    process_id = db.Column(db.String(20))
    status = db.Column(db.Integer)
    def __repr__(self):
        return '<Template %r, command: %r>\n' % (self.name, self.command)
