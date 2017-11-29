from flask import Flask, render_template, request, redirect
from flask import jsonify, url_for, flash, g
from functools import wraps

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker

from application_setup import Base, engine, User
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
from flask_httpauth import HTTPBasicAuth
from random import randint
# *IMPORTS*


auth = HTTPBasicAuth()
# setup flask app
app = Flask(__name__)
# Connect to Database and create database session
Base.metadata.bind = engine
# Create Session
DBSession = sessionmaker(bind=engine)
session = DBSession()
# Set Google Client ID
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read()
)['web']['client_id']


# context processor to pass through
# variables for all url's
@app.context_processor
def utilityProcessor():
    # random string of characters for state
    state = ''.join(random.choice(
        string.ascii_uppercase + string.digits
        ) for x in range(32))
    login_session['state'] = state
    user = dict(
        username=login_session.get('username'),
        email=login_session.get('email'),
        picture=login_session.get('picture'))
    ismaster = isMasterUser()
    return dict(STATE=state, USER=user, ISMASTER=ismaster)


def login_verification(f):
    @wraps(f)
    def check_authentication(*args, **kwargs):
        # if a user is not logged in send to login
        if 'username' in login_session:
            return f(*args, **kwargs)
        else:
            flash("You are not allowed to access there")
            return redirect(url_for('login'))
    return check_authentication


# Home Url
@app.route('/')
def home():
    categories = getAllCategories()
    # swtich between logged in and public templates
    if login_session.get('username') is None:
        return render_template(
            'public_home.html',
            categories=categories,
            route_name='Home')
    return render_template(
        'home.html',
        categories=categories,
        route_name='Home')


# Add an item
@app.route('/item/add', methods=['GET', 'POST'])
@login_verification
def addItem():
    # if post
    if request.method == 'POST':
        item = session.query(Item).filter_by(
                name=request.form['name'],
                sub_category_id=request.form['sub_category_id']).first()
        # item doesn't exist
        if item is None:
            # create new item
            new_item = Item(
                name=request.form['name'],
                description=request.form['description'],
                sub_category_id=request.form['sub_category_id'],
                created_by_id=login_session['user_id'])
            session.add(new_item)
            flash('New Item "%s" Successfully Created' % new_item.name)
            session.commit()
            return redirect(url_for('home'))
        else:
            # if item exists flash error
            flash('Item Already Exists')
            return redirect(url_for('addItem'))
    else:
        # not post render template
        sub_categories = getSubCategory()
        return render_template(
            'item_form.html',
            route_name='Add Item',
            sub_categories=sub_categories)


# Add a SubCategory
@app.route('/category/add', methods=['GET', 'POST'])
@login_verification
def addCategory():
    if request.method == 'POST':
        # attempt to create category
        try:
            new_category = Category(
                name=request.form['name'],
                icon=request.form['icon'],
                created_by_id=login_session['user_id'])
            session.add(new_category)
            session.commit()
            flash('Category "%s" Successfully Created' % new_category.name)
            return redirect(url_for('home'))
        except:
            # if category exists flash error
            session.rollback()
            flash('Category "%s" Already Exists' % request.form['name'])
            return redirect(url_for('addCategory'))
    else:
        # render template
        return render_template(
            'category_form.html',
            route_name='Add Category')


# Add a SubCategory
@app.route('/subcategory/add', methods=['GET', 'POST'])
@login_verification
def addSubCategory():
    # is post
    if request.method == 'POST':
        sub_category = session.query(SubCategory).filter_by(
                name=request.form['name'],
                category_id=request.form['category_id']).first()
        # sub category doesn't exist
        if sub_category is None:
            # create sub category
            new_sub_category = SubCategory(
                name=request.form['name'],
                icon=request.form['icon'],
                category_id=request.form['category_id'],
                created_by_id=login_session['user_id'])
            session.add(new_sub_category)
            # update flash message
            flsh_msg = 'Sub Category "%s" Successfully Created'
            flsh_msg = flsh_msg % new_sub_category.name
            flash(flsh_msg)
            session.commit()
            return redirect(url_for('home'))
        else:
            flash('Sub Category "%s" Already Exists' % request.form['name'])
            return redirect(url_for('addSubCategory'))
    else:
        # render template
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
@login_verification
def editItem(item_id):
    # get item
    editItem = session.query(Item).filter_by(
        id=item_id).first()
    # if item does not exists
    if editItem is None:
        flash("Item does not exist")
        return redirect(url_for('home'))

    if request.method == 'POST':
        if can_crud(editItem) is True:
            # if form
            if request.form['name']:
                # update item
                editItem.name = request.form['name']
                editItem.description = request.form['description']
                editItem.sub_category_id = request.form['sub_category_id']
                flash('Item "%s" Successfully Edited' % editItem.name)
        else:
            flash('You do not have authorization to perform this action')
        return redirect(url_for('home'))
    else:
        sub_categories = getSubCategory()
        if can_crud(editItem) is True:
            return render_template(
                'edit_item.html',
                item=editItem.serialize,
                route_name='Edit Item "%s"' % editItem.name,
                sub_categories=sub_categories)
        else:
            return render_template(
                'view_item.html',
                item=editItem.serialize,
                route_name='View Item "%s"' % editItem.name,
                sub_categories=sub_categories)


# Edit a category
@app.route(
    '/category/<int:category_id>/edit/',
    methods=['GET', 'POST'])
@login_verification
def editCategory(category_id):
    editCategory = session.query(Category).filter_by(
        id=category_id).first()
    # if category does not exists
    if editCategory is None:
        flash("Category does not exist")
        return redirect(url_for('home'))
    if request.method == 'POST':
        if can_crud(editCategory) is True:
            # if form
            if request.form['name']:
                # update category
                flsh_ms = 'Category "%s" Successfully Edited'
                flsh_ms = flsh_ms % editCategory.name
                editCategory.name = request.form['name']
                editCategory.icon = request.form['icon']
                flash(flsh_ms)
        else:
            flash('You do not have authorization to perform this action')
        return redirect(url_for('home'))
    else:
        if can_crud(editCategory) is True:
            return render_template(
                'edit_category.html',
                category=editCategory.serialize,
                route_name='Edit Category "%s"' % editCategory.name)
        else:
            return render_template(
                'view_category.html',
                category=editCategory.serialize,
                route_name='Edit Category "%s"' % editCategory.name)


# Edit a sub category
@app.route(
    '/subcategory/<int:sub_category_id>/edit/',
    methods=['GET', 'POST'])
@login_verification
def editSubCategory(sub_category_id):
    editSubCategory = session.query(SubCategory).filter_by(
        id=sub_category_id).first()
    # if sub category does not exists
    if editSubCategory is None:
        flash("Sub category does not exist")
        return redirect(url_for('home'))
    if request.method == 'POST':
        if can_crud(editSubCategory) is True:
            # if form
            if request.form['name']:
                # update sub category
                flsh_ms = 'Sub Category "%s" Successfully Edited'
                flsh_ms = flsh_ms % editSubCategory.name
                editSubCategory.name = request.form['name']
                editSubCategory.icon = request.form['icon']
                editSubCategory.category_id = request.form['category_id']
                flash(flsh_ms)
        else:
            flash('You do not have authorization to perform this action')
        return redirect(url_for('home'))
    else:
        categories = [category.serialize for category in session.query(
            Category).all()]
        if can_crud(editSubCategory) is True:
            return render_template(
                'edit_sub_category.html',
                sub_category=editSubCategory.serialize,
                route_name='Edit Sub Category "%s"' % editSubCategory.name,
                categories=categories)
        else:
            return render_template(
                'view_sub_category.html',
                sub_category=editSubCategory.serialize,
                route_name='View Sub Category "%s"' % editSubCategory.name,
                categories=categories)


# delete an item
@app.route(
    '/item/<int:item_id>/delete/',
    methods=['GET', 'POST'])
@login_verification
def deleteItem(item_id):
    itemToDelete = session.query(Item).filter_by(
        id=item_id).first()
    # if item to delete does not exists
    if itemToDelete is None:
        flash("Item does not exist")
        return redirect(url_for('home'))
    if can_crud(itemToDelete) is False:
        flash('You do not have authorization to perform this action')
        return redirect(url_for('home'))
    if request.method == 'POST':
        # delete item
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
@login_verification
def deleteCategory(category_id):
    categoryToDelete = session.query(Category).filter_by(
        id=category_id).first()
    # if category to delete does not exists
    if categoryToDelete is None:
        flash("Category does not exist")
        return redirect(url_for('home'))
    if can_crud(categoryToDelete) is False:
        flash('You do not have authorization to perform this action')
        return redirect(url_for('home'))
    if request.method == 'POST':
        # delete category
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
@login_verification
def deleteSubCategory(sub_category_id):
    subCategoryToDelete = session.query(SubCategory).filter_by(
        id=sub_category_id).first()
    # if sub category to delete does not exists
    if subCategoryToDelete is None:
        flash("Sub category does not exist")
        return redirect(url_for('home'))
    if can_crud(subCategoryToDelete) is False:
        flash('You do not have authorization to perform this action')
        return redirect(url_for('home'))
    if request.method == 'POST':
        # delete sub category
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


@app.route('/users/manage', methods=['GET'])
def manageUsers():
    # if a user is not master user
    if isMasterUser() is False:
        # if a user is not logged in let know they are restricted
        if login_session.get('username') is not None:
            flash('Access Restricted')
            return redirect(url_for('home'))
        # if not logged in and not master send to login
        flash('Please Login as Master')
        return redirect(url_for('login'))
    users = session.query(User).all()
    return render_template(
        'manage_users.html',
        users=users,
        route_name='Manage Users')


@app.route('/users/edit/<int:user_id>/', methods=['GET', 'POST'])
def editUser(user_id):
    # if a user is not master user
    if isMasterUser() is False:
        # if a user is not logged in let know they are restricted
        if login_session.get('username') is not None:
            flash('Access Restricted')
            return redirect(url_for('home'))
        # if not logged in and not master send to login
        flash('Please Login as Master')
        return redirect(url_for('login'))
    # get user to edit
    user = session.query(User).filter_by(id=user_id).first()
    # if post then update user
    if request.method == 'POST':
        flsh_msg = 'User "%s" Successfully Edited'
        flsh_msg = flsh_msg % user.name
        # if form
        if request.form['name']:
            # update user info
            user.name = request.form['name']
            user.email = request.form['email']
            user.username = request.form['username']
            user.picture = request.form['picture']
            flash(flsh_msg)
        return redirect(url_for('manageUsers'))
    # otherwise just show template
    else:
        return render_template(
            'edit_user.html',
            user=user)


@app.route('/users/register', methods=['GET', 'POST'])
def signup():
    # if post attempt to create user
    if request.method == 'POST':
        # set default for redirect_url and flsh_msg
        redirect_url = url_for('signup')
        flsh_msg = "An Error Occured"
        # see if user already exists
        try:
            # create new user
            newUser = User(
                name=request.form['name'],
                email=request.form['email'],
                username=request.form['username'],
                picture=request.form['picture'],
                passwd=request.form['passwd'])
            # add and commit
            session.add(newUser)
            session.commit()
            # set login session with new user
            login_session['username'] = newUser.username
            login_session['email'] = newUser.email
            login_session['picture'] = newUser.picture
            # update flash message
            flsh_msg = "Welcome, %s" % newUser.username
            redirect_url = url_for('home')
        except:
            # user exists
            # update flash message
            flsh_msg = "User already exists."
        flash(flsh_msg)
        return redirect(redirect_url)
    else:
        # if not post then render template
        return render_template(
            'register_form.html',
            route_name='Register')


@app.route('/users/login', methods=['GET', 'POST'])
def login():
    # if post
    if request.method == 'POST':
        # attempt to get user
        user = session.query(User).filter_by(
            email=request.form['email']).first()
        # if user exists
        if user is not None:
            if user.verify_password(request.form['passwd']):
                login_session['username'] = user.username
                login_session['email'] = user.email
                login_session['picture'] = user.picture
                login_session['user_id'] = user.id
                flsh_msg = 'Welcome, %s' % user.username
                redirect_url = redirect(url_for('home'))
            else:
                # user doesn't exists
                # update flash message and redirect url
                flsh_msg = 'Incorrect Login Details'
                redirect_url = redirect(url_for('login'))
        flash(flsh_msg)
        return redirect_url
    else:
        # if not post then render template
        return render_template(
            'login_page.html', route_name='Login')


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


@app.route('/disconnect')
def disconnect():
    access_token = login_session.get('access_token')
    # if access token present
    if access_token is not None:
        url = 'https://accounts.google.com/o/oauth2/revoke?token={}'
        url = url.format(login_session['access_token'])
        h = httplib2.Http()
        # make http request to google to revoke token
        result = h.request(url, 'GET')[0]
        # successful result
        if result['status'] == '200':
            clearLoginSession()
            flash('Logged Out')
        else:
            flash('Could not log you out.')
    else:
        # if no access token but there is a login session
        if login_session.get('username') is not None:
            # clear login session
            clearLoginSession()
            flash('Logged Out')
        else:
            flash('Not Logged in')
    return redirect(url_for('home'))


# debugging purposes
@app.route('/debug')
def debug():
    users = [group.serialize for group in session.query(User).all()]
    categories = [group.serialize for group in session.query(Category).all()]
    sub_categories = [group.serialize for group in session.query(
        SubCategory).all()]
    items = [item.serialize for item in session.query(Item).all()]
    data = [
        {'name': 'User', 'data': users},
        {'name': 'Category', 'data': categories},
        {'name': 'Sub Category', 'data': sub_categories},
        {'name': 'Item', 'data': items}
    ]

    return render_template('debug.html', data=data)


# Helper Functions
# put all the various bits of info together
# to have the category info along with corrolating info
def getAllCategories(with_items=True):
    sub_categories = [group.serialize for group in session.query(
        SubCategory).all()]
    categories = []
    for category_raw in session.query(Category).all():
        category_info = category_raw.serialize
        sub_category_arr = []
        # get sub categories
        for sub_cat in sub_categories:
            if sub_cat['category_id'] == category_info['id']:
                # determins if lower depth info should be obtained
                if with_items:
                    # sub category with item information
                    sub_cat['item_info'] = [
                        item.serialize for item in session.query(
                            Item).filter_by(
                                sub_category_id=sub_cat['id']).all()]
                    # if there is items for this category
                    if sub_cat['item_info'] is not 0:
                        sub_category_arr.append(sub_cat)
                else:
                    sub_category_arr.append(sub_cat)
        # if category has sub categories
        if sub_category_arr is not None:
            category_info['sub_categories'] = sub_category_arr
            categories.append(category_info)

    return categories


def clearLoginSession():
    if login_session.get('username') is not None:
        del login_session['username']
    if login_session.get('user_id') is not None:
        del login_session['user_id']
    if login_session.get('email') is not None:
        del login_session['email']
    if login_session.get('picture') is not None:
        del login_session['picture']
    if login_session.get('access_token') is not None:
        del login_session['access_token']
    if login_session.get('gplus_id') is not None:
        del login_session['gplus_id']


def createUser(login_session):
    # create user from login session
    try:
        newUser = User(
            name=login_session['username'],
            email=login_session['email'],
            picture=login_session['picture'],
            username="GOOGLE-" + login_session['email'],
            passwd="")
        session.add(newUser)
        session.commit()
        user = session.query(User).filter_by(
            email=login_session['email']).first()
        return user.id
    except:
        return None


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
    # determins if lower depth info should be obtained
    if with_category:
        # sub category with it's corrolating category info
        categories = [category.serialize for category in session.query(
            Category).all()]
        for sub_cat in sub_categories:
            sub_cat['category'] = [
                cat for cat in categories
                if cat['id'] == sub_cat['category_id']][0]
    return sub_categories


def getRandomCategory():
    categories = [category.serialize for category in session.query(
        Category).all()]
    randomCategory = categories[randint(0, len(categories) - 1)]
    sub_categories = [group.serialize for group in session.query(
        SubCategory).filter_by(category_id=randomCategory['id'])]
    sub_category_arr = []
    # get sub categories
    for sub_cat in sub_categories:
        # sub category with item information
        sub_cat['items'] = [
            item.serialize for item in session.query(
                Item).filter_by(
                    sub_category_id=sub_cat['id']).all()]
        # if there is items for this sub category
        if sub_cat['items'] is not 0:
            sub_category_arr.append(sub_cat)
    # if category has sub categories
    if sub_category_arr is not None:
        randomCategory['sub_categories'] = sub_category_arr
    return dict(Category=randomCategory)


# check if the currently logged in user is the master user
def isMasterUser():
    if login_session.get('email') is not None:
        user = session.query(User).filter_by(
            email=login_session['email']).first()
        if user is not None:
            return user.id == 1
    return False


# verify if item/category/sub category can be CRUD
def can_crud(item):
    if item is not None and item.created_by_id is not None:
        return item.created_by_id == login_session.get('user_id')
    return False


# token/login verification for api calls
@auth.verify_password
def verify_password(username_or_token, password):
    # check for logged in user
    if login_session.get('username') is not None:
        return True
    # Try to see if it's a token first
    user_id = User.verify_auth_token(username_or_token)
    if user_id:
        user = session.query(User).filter_by(id=user_id).one()
    else:
        user = session.query(User).filter_by(
            username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


# get token from login credentials for easier api calls
@app.route('/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})


# Catalog information api call in JSON format
@app.route('/catalog.json', methods=['GET', 'POST'])
@auth.login_required
def catalogJSON():
    catalog = getRandomCategory()
    return jsonify(catalog), 201


# start application server
if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
