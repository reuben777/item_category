from flask import Flask, render_template, request, redirect
from flask import jsonify, url_for, flash

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker

from application_setup import Base, engine, UserGroup, User, AuthInfo
from application_setup import Category, Item, SubCategory

from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

# setup flask app
app = Flask(__name__)

# Connect to Database and create database session
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read()
)['web']['client_id']


@app.context_processor
def utilityProcessor():
    state = ''.join(random.choice(
        string.ascii_uppercase + string.digits
        ) for x in range(32))
    login_session['state'] = state
    user = dict(
        username=login_session.get('username'),
        email=login_session.get('email'),
        picture=login_session.get('picture'))
    return dict(STATE=state, USER=user)


@app.route('/')
def home():
    categories = getAllCategories()
    return render_template(
        'home.html',
        categories=categories,
        route_name='Home')


# Add an item
@app.route('/item/add', methods=['GET', 'POST'])
def addItem():
    if request.method == 'GET':
        sub_categories = getSubCategory()
        return render_template(
            'item_form.html',
            route_name='Add Item',
            sub_categories=sub_categories)
    if request.method == 'POST':
        new_item = Item(
            name=request.form['name'],
            sub_category_id=request.form['sub_category_id'])
        session.add(new_item)
        flash('New Item "%s" Successfully Created' % new_item.name)
        session.commit()
        return redirect(url_for('home'))


# Add a SubCategory
@app.route('/category/add', methods=['GET', 'POST'])
def addCategory():
    if request.method == 'POST':
        category = session.query(Category).filter_by(
                name=request.form['name']).first()
        if category is None:
            new_category = Category(
                name=request.form['name'],
                icon=request.form['icon'])
            session.add(new_category)
            flash('Category "%s" Successfully Created' % new_category.name)
            session.commit()
        else:
            flash('Category "%s" Already Exists' % request.form['name'])
        return redirect(url_for('home'))
    else:
        return render_template(
            'category_form.html',
            route_name='Add Category')


# Add a SubCategory
@app.route('/subcategory/add', methods=['GET', 'POST'])
def addSubCategory():
    if request.method == 'POST':
        sub_category = session.query(SubCategory).filter_by(
                name=request.form['name'],
                category_id=request.form['category_id']).first()
        if sub_category is None:
            new_sub_category = SubCategory(
                name=request.form['name'],
                icon=request.form['icon'],
                category_id=request.form['category_id'])
            session.add(new_sub_category)
            flsh_msg = 'Sub Category "%s" Successfully Created'
            flsh_msg = flsh_msg % new_sub_category.name
            flash(flsh_msg)
            session.commit()
        else:
            flash('Sub Category "%s" Already Exists' % request.form['name'])
        return redirect(url_for('home'))
    else:
        categories = [category.serialize for category in session.query(
            Category).all()]
        return render_template(
            'sub_category_form.html',
            route_name='Add Sub Category',
            categories=categories)


# Edit an item
@app.route(
    '/item/<int:item_id>/edit/',
    methods=['GET', 'POST'])
def editItem(item_id):
    # if 'username' not in login_session:
    #     return redirect('/login')
    editItem = session.query(Item).filter_by(
        id=item_id).first()
    if request.method == 'POST':
        if request.form['name']:
            editItem.name = request.form['name']
            editItem.sub_category_id = request.form['sub_category_id']
            flash('Item "%s" Successfully Edited' % editItem.name)
            return redirect(url_for('home'))
    else:
        sub_categories = getSubCategory()
        return render_template(
            'edit_item.html',
            item=editItem.serialize,
            route_name='Edit Item "%s"' % editItem.name,
            sub_categories=sub_categories)


# Edit a category
@app.route(
    '/category/<int:category_id>/edit/',
    methods=['GET', 'POST'])
def editCategory(category_id):
    # if 'username' not in login_session:
    #     return redirect('/login')
    editCategory = session.query(Category).filter_by(
        id=category_id).first()
    if request.method == 'POST':
        if request.form['name']:
            flsh_ms = 'Category "%s" Successfully Edited'
            flsh_ms = flsh_ms % editCategory.name
            editCategory.name = request.form['name']
            editCategory.icon = request.form['icon']
            flash(flsh_ms)
            return redirect(url_for('home'))
    else:
        return render_template(
            'edit_category.html',
            category=editCategory.serialize,
            route_name='Edit Category "%s"' % editCategory.name)


# Edit a sub category
@app.route(
    '/subcategory/<int:sub_category_id>/edit/',
    methods=['GET', 'POST'])
def editSubCategory(sub_category_id):
    # if 'username' not in login_session:
    #     return redirect('/login')
    editSubCategory = session.query(SubCategory).filter_by(
        id=sub_category_id).first()
    if request.method == 'POST':
        if request.form['name']:
            flsh_ms = 'Sub Category "%s" Successfully Edited'
            flsh_ms = flsh_ms % editSubCategory.name
            editSubCategory.name = request.form['name']
            editSubCategory.icon = request.form['icon']
            editSubCategory.category_id = request.form['category_id']
            flash(flsh_ms)
            return redirect(url_for('home'))
    else:
        categories = [category.serialize for category in session.query(
            Category).all()]
        return render_template(
            'edit_sub_category.html',
            sub_category=editSubCategory.serialize,
            route_name='Edit Sub Category "%s"' % editSubCategory.name,
            categories=categories)


# delete an item
@app.route(
    '/item/<int:item_id>/delete/',
    methods=['GET', 'POST'])
def deleteItem(item_id):
    # if 'username' not in login_session:
    #     return redirect('/login')
    itemToDelete = session.query(Item).filter_by(
        id=item_id).first()
    if request.method == 'POST':
        session.delete(itemToDelete)
        flash('Item "%s" Successfully Deleted' % itemToDelete.name)
        session.commit()
        return redirect(url_for('home'))
    else:
        return render_template(
            'delete_form.html',
            name=itemToDelete.name,
            type='item')


# delete a sub category
@app.route(
    '/category/<int:category_id>/delete/',
    methods=['GET', 'POST'])
def deleteCategory(category_id):
    # if 'username' not in login_session:
    #     return redirect('/login')
    categoryToDelete = session.query(Category).filter_by(
        id=category_id).first()
    if request.method == 'POST':
        session.delete(categoryToDelete)
        flash('Category "%s" Successfully Deleted' % categoryToDelete.name)
        session.commit()
        return redirect(url_for('home'))
    else:
        return render_template(
            'delete_form.html',
            name=categoryToDelete.name,
            type='category')


# delete a sub category
@app.route(
    '/subcategory/<int:sub_category_id>/delete/',
    methods=['GET', 'POST'])
def deleteSubCategory(sub_category_id):
    # if 'username' not in login_session:
    #     return redirect('/login')
    subCategoryToDelete = session.query(SubCategory).filter_by(
        id=sub_category_id).first()
    if request.method == 'POST':
        session.delete(subCategoryToDelete)
        fls_msg = 'Sub Category "%s" Successfully Deleted'
        fls_msg = fls_msg % subCategoryToDelete.name
        flash(fls_msg)
        session.commit()
        return redirect(url_for('home'))
    else:
        return render_template(
            'delete_form.html',
            name=subCategoryToDelete.name,
            type='sub category')


@app.route('/users/manage', methods=['GET', 'POST'])
def manageUsers():
    if request.method == 'POST':
        return redirect(url_for('home'))
    else:
        users = session.query(User).all()
        user_groups = session.query(UserGroup).all()
        return render_template(
            'manage_users.html',
            users=users,
            route_name='Manage Users',
            user_groups=user_groups)


@app.route('/users/edit/<int:user_id>/', methods=['GET', 'POST'])
def editUser(user_id):
    user = session.query(User).filter_by(id=user_id).first()
    if request.method == 'POST':
        flsh_msg = 'User "%s" Successfully Edited'
        flsh_msg = flsh_msg % user.name
        if request.form['name']:
            user.name = request.form['name']
            user.email = request.form['email']
            user.username = request.form['username']
            user.user_group_id = request.form['user_group_id']
            user.picture = request.form['picture']
            flash(flsh_msg)
        return redirect(url_for('manageUsers'))
    else:
        user_groups = session.query(UserGroup).all()
        return render_template(
            'edit_user.html',
            user=user,
            user_groups=user_groups)


# debugging purposes
@app.route('/debug')
def debug():
    groups = [group.serialize for group in session.query(UserGroup).all()]
    users = [group.serialize for group in session.query(User).all()]
    categories = [group.serialize for group in session.query(Category).all()]
    sub_categories = [group.serialize for group in session.query(
        SubCategory).all()]
    items = [item.serialize for item in session.query(Item).all()]
    authorization_info = [auth.serialize for auth in session.query(
        AuthInfo).all()]
    data = [
        {'name': 'UserGroup', 'data': groups},
        {'name': 'User', 'data': users},
        {'name': 'Category', 'data': categories},
        {'name': 'Sub Category', 'data': sub_categories},
        {'name': 'Item', 'data': items},
        {'name': 'AuthInfo', 'data': authorization_info}
    ]

    return render_template('debug.html', data=data)


def getAllCategories(with_items=True):
    sub_categories = [group.serialize for group in session.query(
        SubCategory).all()]
    categories = []
    for category_raw in session.query(Category).all():
        category_info = category_raw.serialize
        sub_category_arr = []
        for sub_cat in sub_categories:
            if sub_cat['category_id'] == category_info['id']:
                if with_items:
                    sub_cat['item_info'] = [
                        item.serialize for item in session.query(
                            Item).filter_by(
                                sub_category_id=sub_cat['id']).all()]
                    if sub_cat['item_info'] is not 0:
                        sub_category_arr.append(sub_cat)
                else:
                    sub_category_arr.append(sub_cat)

        if sub_category_arr is not None:
            category_info['sub_categories'] = sub_category_arr
            categories.append(category_info)

    return categories


@app.route('/gconnect', methods=['POST'])
def gconntect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data.decode('utf-8')

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = 'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={}'
    url = (url.format(access_token))
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['provider'] = 'google'
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # See if user exists, if it doesn't make a new accounts
    user_id = getUserID(data['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += '" class="rounded img-fluid" >'
    flash("you are now logged in as {}".format(login_session['username']))
    return output


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    print "access_token %s" % access_token
    if access_token is None:
        flash('Not Logged In')
    else:
        url = 'https://accounts.google.com/o/oauth2/revoke?token={}'
        url = url.format(login_session['access_token'])
        h = httplib2.Http()
        result = h.request(url, 'GET')[0]
        print "result %s" % result
        # result = result.decode('utf-8')

        if result['status'] == '200':
            del login_session['access_token']
            del login_session['gplus_id']
            del login_session['username']
            del login_session['email']
            del login_session['picture']
            flash('Logged Out')
        else:
            flash('Could not log out')
    return redirect(url_for('home'))

# Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


def getSubCategory(with_category=True):
    sub_categories = [category.serialize for category in session.query(
        SubCategory).all()]
    if with_category:
        categories = [category.serialize for category in session.query(
            Category).all()]
        for sub_cat in sub_categories:
            sub_cat['category'] = [
                cat for cat in categories
                if cat['id'] == sub_cat['category_id']][0]
    return sub_categories


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
