from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from itsdangerous import (
    TimedJSONWebSignatureSerializer as Serializer,
    BadSignature,
    SignatureExpired)
from passlib.apps import custom_app_context as pwd_context
import random
import string

Base = declarative_base()
secret_key = ''.join(
    random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    email = Column(String(100))
    username = Column(String(100), unique=True)
    picture = Column(String(100))
    password_hash = Column(String(100))

    def __init__(
        self, name, email, username,
            picture, passwd):
        self.name = name
        self.email = email
        self.username = username
        self.picture = picture
        self.password_hash = self.hash_password(passwd)

    def hash_password(self, password):
        return pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(secret_key, expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(secret_key)
        try:
            data = s.loads(token)
        except SignatureExpired:
            # Valid Token, but expired
            return None
        except BadSignature:
            # Invalid Token
            return None
        user_id = data['id']
        return user_id

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
           'id': self.id,
           'name': self.name,
           'email': self.email,
           'username': self.username,
           'picture': self.picture
           }


class Category(Base):
    __tablename__ = 'category'

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    icon = Column(String(40), nullable=False)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'name': self.name,
            'icon': self.icon
            }


class SubCategory(Base):
    __tablename__ = 'sub_category'

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    icon = Column(String(40), nullable=False)
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'name': self.name,
            'icon': self.icon,
            'category_id': self.category_id
            }


class Item(Base):
    __tablename__ = 'item'

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    description = Column(String(200), nullable=True)
    sub_category_id = Column(Integer, ForeignKey('sub_category.id'))
    sub_category = relationship(SubCategory)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'sub_category_id': self.sub_category_id
            }


engine = create_engine('sqlite:///catalog.db')


Base.metadata.create_all(engine)
