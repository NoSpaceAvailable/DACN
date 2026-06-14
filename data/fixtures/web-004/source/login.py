from app import *
import string, random
from flask import Flask, make_response
import re


def generate_cookie(length=20):
    characters = string.ascii_letters + string.digits
    random_string = ''.join(random.choice(characters) for _ in range(length))
    return random_string


def validEmail(email):
    regex = "^[a-zA-Z0-9-_!#$%&'*+-/=?^_`{|}~']+@[a-zA-Z0-9]+\.[a-z]{1,3}$"
    return re.search(regex, email)


def isadmin():
    if session and session['email'] not in ['', 'Error']:
        cursor = get_conn().cursor()
        query = 'SELECT privilege FROM users WHERE email=%s'
        cursor.execute(query, (session['email']))
        if cursor.fetchone()['privilege'] == 'admin':
            cursor.close()
            return True
    return False


def getPass():
    if session and session['email'] not in ['', 'Error']:
        cursor = get_conn().cursor()
        query = 'SELECT password FROM users WHERE email=%s'
        cursor.execute(query, (session['email']))
        return cursor.fetchone()['password']
    return ''


def authenticate(email='', password=''):
    name = ''
    cursor = get_conn().cursor()
    if email and password:
        if validEmail(email):
            query = "SELECT * FROM users WHERE email = %s AND password = %s"
            cursor.execute(query, (email, password))
            user = cursor.fetchone()
            if user:
                name = user['name']
                session['email'] = user['email']
                message = "View Details"
                if isadmin():
                    message = "Edit Details"
                return render_template('userHome.html', welcome=name, flag=True, message=message)
    message = "Sorry, this user doesn't exist"
    cursor.close()
    return render_template('login.html', error=message)


def injectableFunction():
    cursor = get_conn().cursor()
    cookie = request.cookies.get("trackingID")
    query = f"SELECT * FROM trackingid WHERE cookie='{cookie}';"
    try:
        cursor.execute(query)
        badSQLflag = False
        result = cursor.fetchone()
    except Exception:
        badSQLflag = True
        result = None

    session['trackingID'] = cookie

    if not result or badSQLflag:
        session['email'] = 'Error'
    else:
        session['email'] = ''
    cursor.close()
    return


@app.route('/login', methods=["POST"])
def login():
    injectableFunction()
    return render_template('login.html')


@app.route('/submit', methods=["POST", "GET"])
def submit():
    if not session or session['email'] in ['', 'Error']:
        email = request.form['email']
        password = request.form['password']
    else:
        email = session['email']
        password = getPass()
    return authenticate(email, password)


@app.route('/displaydetails', methods=['POST'])
def display():
    single = {'name': "Pay-Per-Ride", 'details': "...", 'price': "$2.90"}
    week = {'name': "7-Day Pass", 'details': "...", 'price': "$34"}
    month = {'name': "30-Day Pass", 'details': "...", 'price': "$132"}
    pass_type = request.form.get('passType')
    if pass_type == 'single':
        return render_template('displaydetails.html', product=single, isadmin=isadmin())
    elif pass_type == 'week':
        return render_template('displaydetails.html', product=week, isadmin=isadmin())
    else:
        return render_template('displaydetails.html', product=month, isadmin=isadmin())


@app.route('/changeprice', methods=['POST'])
def changeprice():
    flag = """flag{cheaper_prices_in_NYC_PLZ}"""
    if 'Price' in request.form and request.form['Price'].strip():
        if request.form['Price'] in ['2.75', '$2.75', '2.75$']:
            return render_template('changeprice.html', isadmin=isadmin(), showflag=flag)
    else:
        return render_template('changeprice.html', isadmin=isadmin(), showflag='')


@app.route('/logout', methods=["POST"])
def logout():
    message = "View Details"
    try:
        session['email'] = ''
        name = 'You have Successfully Logged Out'
    except Exception:
        ...
    return render_template('userHome.html', welcome=name, flag=False, message=message)
