#from datetime import datetime
#import hashlib
#from werkzeug.security import generate_password_hash, check_password_hash
#from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
#from markdown import markdown
#import bleach
#from flask import current_app, request, url_for
#from flask_login import UserMixin, AnonymousUserMixin
#from app.exceptions import ValidationError
from . import db


class Serv(db.Model):
    __tablename__ = 'servs'
    id = db.Column(db.Integer, primary_key=True)
    servname = db.Column(db.String(128))
    ip = db.Column(db.String(128))
    consulname = db.Column(db.String(128))
    port = db.Column(db.Integer)

    def __repr__(self):
        return '<Serv %r>' % self.servname


