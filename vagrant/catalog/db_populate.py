from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from application_setup import Base, User, UserGroup, Category, Item
from application_setup import AuthInfo, SubCategory

engine = create_engine('sqlite:///catalog.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

session = DBSession()

user_groups = [
    "Group 1",
    "Group 2"
]

users = [
    {'username': 'Master', 'password': '123456', 'user_group_id': 1},
    {'username': 'John', 'password': 'test', 'user_group_id': 2},
    {'username': 'Sarah', 'password': 'test', 'user_group_id': 2},
    {'username': 'Dolly', 'password': 'test', 'user_group_id': 3},
    {'username': 'Claire', 'password': 'test', 'user_group_id': 3},
]

categories = [
    {'name': 'Entertainment', 'icon': 'fa-music'},
    {'name': 'Places', 'icon': 'fa-building-o'},
    {'name': 'Parks and Playgrounds', 'icon': 'fa-tree'},
    {'name': 'Other', 'icon': 'fa-list'}
]

sub_categories = [
    {'name': 'Bars', 'icon': 'fa-glass', 'category_id': 1},
    {'name': 'Clubs', 'icon': 'fa-microphone', 'category_id': 1},
    {'name': 'Lounges', 'icon': 'fa-building', 'category_id': 1},
    {'name': 'Hotels', 'icon': 'fa-home', 'category_id': 2},
    {'name': 'Museums', 'icon': 'fa-picture-o', 'category_id': 2},
    {'name': 'Restuarants', 'icon': 'fa-cutlery', 'category_id': 2},
    {'name': 'Parks', 'icon': 'fa-paw', 'category_id': 3},
    {'name': 'Recreation Centers', 'icon': 'fa-star-o', 'category_id': 3},
]

items = [
    {'name': 'Bar 1', 'sub_category_id': 1},
    {'name': 'Bar 2', 'sub_category_id': 1},
    {'name': 'Club 1', 'sub_category_id': 2},
    {'name': 'Club 2', 'sub_category_id': 2},
    {'name': 'Hotel 1', 'sub_category_id': 4},
    {'name': 'Hotel 2', 'sub_category_id': 4},
    {'name': 'Museum 1', 'sub_category_id': 5},
    {'name': 'Museum 2', 'sub_category_id': 5},
    {'name': 'Restuarant 1', 'sub_category_id': 6},
    {'name': 'Restuarant 2', 'sub_category_id': 6},
    {'name': 'Park 1', 'sub_category_id': 7},
    {'name': 'Recreation Center 1', 'sub_category_id': 8},
]

auth_info = [
    {'item_id': 1, 'user_group_id': 1},
    {'item_id': 2, 'user_group_id': 1},
    {'item_id': 3, 'user_group_id': 2},
    {'item_id': 4, 'user_group_id': 2},
    {'item_id': 5, 'user_group_id': 2},
    {'item_id': 6, 'user_group_id': 1},
    {'item_id': 7, 'user_group_id': 1},
    {'item_id': 8, 'user_group_id': 1},
    {'item_id': 9, 'user_group_id': 3},
    {'item_id': 10, 'user_group_id': 3},
    {'item_id': 11, 'user_group_id': 3},
    {'item_id': 12, 'user_group_id': 3},
    {'item_id': 1, 'user_group_id': 2},
    {'item_id': 1, 'user_group_id': 3},
]


def setupGroups():
    # Setup Master UserGroup
    master = UserGroup(name='Master')
    session.add(master)
    print "Created Group - Master"
    for group_name in user_groups:
        new_group = UserGroup(name=group_name)
        print "Created Group - %s" % group_name
        session.add(new_group)
    session.commit()


def setupUsers():
    setupGroups()
    for user in users:
        email = '%s@gmail.com' % user['username'].lower()
        new_user = User(
            name=user['username'],
            email=email,
            username=user['username'].lower(),
            picture='/static/_blank_user.png',
            user_group_id=user['user_group_id'])
        print "Created User - %s" % new_user.serialize
        session.add(new_user)
    session.commit()


def setupCategories():
    for category in categories:
        new_category = Category(name=category['name'], icon=category['icon'])
        print "Created Category - %s" % new_category.serialize
        session.add(new_category)
    session.commit()
    setupSubCategories()


def setupSubCategories():
    for sub_category in sub_categories:
        new_sub_category = SubCategory(
            name=sub_category['name'],
            icon=sub_category['icon'],
            category_id=sub_category['category_id'])
        print "Created Sub Category - %s" % new_sub_category.serialize
        session.add(new_sub_category)
    session.commit()


def setupItems():
    for item in items:
        new_item = Item(
            name=item['name'],
            sub_category_id=item['sub_category_id'])
        print "Created Item - %s" % new_item.serialize
        session.add(new_item)
    session.commit()


def setupAuth():
    for auth in auth_info:
        new_auth = AuthInfo(
            item_id=auth['item_id'],
            user_group_id=auth['user_group_id'])
        print "Created Auth Link - %s" % new_auth.serialize
        session.add(new_auth)
    session.commit()


def clean_db():
    # Clean Db
    meta = Base.metadata
    con = engine.connect()
    trans = con.begin()
    for name, table in meta.tables.items():
        print table.delete()
        con.execute(table.delete())
    trans.commit()


clean_db()
setupUsers()
setupCategories()
setupItems()
setupAuth()
