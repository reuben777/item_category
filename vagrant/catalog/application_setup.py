from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class UserGroup(Base):
    __tablename__ = 'user_group'

    id = Column(Integer, primary_key=True)
    name = Column(String(80), unique=True)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'name': self.name
            }


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    email = Column(String(100))
    username = Column(String(100), unique=True)
    picture = Column(String(100))
    user_group_id = Column(Integer, ForeignKey('user_group.id'))
    user_group = relationship(UserGroup)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
           'id': self.id,
           'name': self.name,
           'email': self.email,
           'username': self.username,
           'picture': self.picture,
           'user_group_id': self.user_group_id
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
    sub_category_id = Column(Integer, ForeignKey('sub_category.id'))
    sub_category = relationship(SubCategory)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'name': self.name,
            'sub_category_id': self.sub_category_id
            }


class AuthInfo(Base):
    __tablename__ = 'auth_info'

    id = Column(Integer, primary_key=True)
    item_id = Column(Integer, ForeignKey('item.id'))
    item = relationship(Item)
    user_group_id = Column(Integer, ForeignKey('user_group.id'))
    user_group = relationship(UserGroup)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'item_id': self.item_id,
            'user_group_id': self.user_group_id,
            }


engine = create_engine('sqlite:///catalog.db')


Base.metadata.create_all(engine)
