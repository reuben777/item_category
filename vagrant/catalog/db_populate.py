from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from application_setup import Base, User, Category, Item, SubCategory

engine = create_engine('sqlite:///catalog.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

session = DBSession()

users = [
    {'username': 'Master', 'password': '123456'},
    {'username': 'John', 'password': 'test123'},
    {'username': 'Sarah', 'password': 'test123'},
    {'username': 'Dolly', 'password': 'test123'},
    {'username': 'Claire', 'password': 'test123'},
]

categories = [
    {'name': 'Entertainment', 'icon': 'fa-music',
        'created_by_id': 1},
    {'name': 'Places', 'icon': 'fa-building-o',
        'created_by_id': 1},
    {'name': 'Parks and Playgrounds', 'icon': 'fa-tree',
        'created_by_id': 1},
    {'name': 'Other', 'icon': 'fa-list',
        'created_by_id': 5}
]

sub_categories = [
    {'name': 'Bars', 'icon': 'fa-glass', 'category_id': 1,
        'created_by_id': 2},
    {'name': 'Clubs', 'icon': 'fa-microphone', 'category_id': 1,
        'created_by_id': 3},
    {'name': 'Lounges', 'icon': 'fa-building', 'category_id': 1,
        'created_by_id': 4},
    {'name': 'Hotels', 'icon': 'fa-home', 'category_id': 2,
        'created_by_id': 2},
    {'name': 'Museums', 'icon': 'fa-picture-o', 'category_id': 2,
        'created_by_id': 5},
    {'name': 'Restuarants', 'icon': 'fa-cutlery', 'category_id': 2,
        'created_by_id': 2},
    {'name': 'Parks', 'icon': 'fa-paw', 'category_id': 3,
        'created_by_id': 5},
    {'name': 'Recreation Centers', 'icon': 'fa-star-o', 'category_id': 3,
        'created_by_id': 1},
]

items = [
    {'name': 'Bar 1', 'description': 'description', 'sub_category_id': 1,
        'created_by_id': 2},
    {'name': 'Bar 2', 'description': 'description', 'sub_category_id': 1,
        'created_by_id': 3},
    {'name': 'Club 1', 'description': 'description', 'sub_category_id': 2,
        'created_by_id': 2},
    {'name': 'Club 2', 'description': 'description', 'sub_category_id': 2,
        'created_by_id': 4},
    {'name': 'Hotel 1', 'description': 'description', 'sub_category_id': 4,
        'created_by_id': 2},
    {'name': 'Hotel 2', 'description': 'description', 'sub_category_id': 4,
        'created_by_id': 1},
    {'name': 'Museum 1', 'description': 'description', 'sub_category_id': 5,
        'created_by_id': 1},
    {'name': 'Museum 2', 'description': 'description', 'sub_category_id': 5,
        'created_by_id': 2},
    {'name': 'Restuarant 1',
        'description': 'description', 'sub_category_id': 6,
        'created_by_id': 2},
    {'name': 'Restuarant 2',
        'description': 'description', 'sub_category_id': 6,
        'created_by_id': 5},
    {'name': 'Park 1',
        'description': 'description', 'sub_category_id': 7,
        'created_by_id': 2},
    {'name': 'Recreation Center 1',
        'description': 'description', 'sub_category_id': 8,
        'created_by_id': 5},
]


def getRandomUserId():
    return randint(1, len(users))


def setupUsers():
    for user in users:
        email = '%s@gmail.com' % user['username'].lower()
        new_user = User(
            name=user['username'],
            email=email,
            username=user['username'].lower(),
            picture='/static/_blank_user.png',
            passwd=user['password'])
        print "Created User - %s" % new_user.serialize
        session.add(new_user)
    session.commit()


def setupCategories():
    for category in categories:
        new_category = Category(
            name=category['name'],
            icon=category['icon'],
            created_by_id=category['created_by_id'])
        print "Created Category - %s" % new_category.serialize
        session.add(new_category)
    session.commit()
    setupSubCategories()


def setupSubCategories():
    for sub_category in sub_categories:
        new_sub_category = SubCategory(
            name=sub_category['name'],
            icon=sub_category['icon'],
            category_id=sub_category['category_id'],
            created_by_id=sub_category['created_by_id'])
        print "Created Sub Category - %s" % new_sub_category.serialize
        session.add(new_sub_category)
    session.commit()


def setupItems():
    for item in items:
        new_item = Item(
            name=item['name'],
            description=item['description'],
            sub_category_id=item['sub_category_id'],
            created_by_id=item['created_by_id'])
        print "Created Item - %s" % new_item.serialize
        session.add(new_item)
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
