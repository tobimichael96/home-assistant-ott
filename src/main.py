import json
import logging
import os
import random
import sqlite3
from datetime import datetime
from functools import wraps

import requests
from authlib.integrations.flask_client import OAuth
from flask import Flask, redirect, url_for, session, request, jsonify, render_template, send_from_directory

import constants as const

app = Flask(__name__)
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)
app.secret_key = ''.join([str(random.randint(0, 9)) for _ in range(64)])
database_file = '/data/database.db'
allowed_users = os.getenv('ALLOWED_USERS').split(",")

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv('CLIENT_ID'),
    client_secret=os.getenv('CLIENT_SECRET'),
    authorize_params=None,
    access_token_params=None,
    refresh_token_url=None,
    refresh_token_params=None,
    scope='email profile',
    client_kwargs={'scope': 'openid email profile'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration'
)


def authorize(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Check if user is logged in
        if 'google_token' in session:
            user = google.parse_id_token(session['google_token'], None)
            email = user['email']
            if email not in allowed_users:
                return f'Sorry, {email}! You are not allowed.'
        else:
            return redirect(url_for('login'))

        # Call the original function if user is allowed
        return func(*args, **kwargs)

    return wrapper


@app.route('/')
def index():
    return 'Nothing to see here.'


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')


@app.route('/login')
def login():
    return google.authorize_redirect(redirect_uri=url_for('auth', _external=True, _scheme='https'))


@app.route('/oauth2/callback')
def auth():
    token = google.authorize_access_token()
    if token is None:
        return jsonify({'Status': 'Something went wrong!'}), 500
    session['google_token'] = token
    return redirect(url_for('api_show_database'))


@app.route('/logout')
def logout():
    session.pop('google_token', None)
    return redirect(url_for('index'))


@app.route('/api/show')
@authorize
def api_show_database():
    try:
        conn = create_connection(database_file)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT otp, url, valid, created, used
            FROM data;
        ''')
        columns = [column[0] for column in cursor.description]
        result = []
        for row in cursor.fetchall():
            row_dict = dict(zip(columns, row))
            result.append(row_dict)
        conn.commit()
        conn.close()
        return jsonify({'Status': 'Fetched database successfully.', 'Results': result}), 200
    except sqlite3.Error as e:
        logging.error(e)
        return jsonify({'Status': 'Something went wrong!'}), 500


@app.route('/api/clear/<otp>')
@authorize
def api_clear_database(otp):
    try:
        conn = create_connection(database_file)
        cursor = conn.cursor()
        if otp == "all":
            cursor.execute('''
                DELETE FROM data;
            ''')
            logging.info("All data in the table 'data' has been deleted.")
        else:
            cursor.execute('''
                DELETE FROM data 
                WHERE otp = ?;
                ''', (otp,))
            logging.info(f"Rows with otp '{otp}' deleted successfully.")
        conn.commit()
        conn.close()
        return jsonify({'Status': 'Clearing the database worked!'}), 200
    except sqlite3.Error as e:
        logging.error(e)
        return jsonify({'Status': 'Something went wrong!'}), 500


@app.route('/api/generate')
@authorize
def api_generate():
    param_dummy = request.args.get("dummy")

    otp = ''.join([str(random.randint(0, 9)) for _ in range(16)])
    url = f"{request.host_url}trigger/{otp}".replace('http://', 'https://', 1)

    if param_dummy == "true":
        insert_otp(otp, url, False)
    else:
        insert_otp(otp, url, True)

    return jsonify({'URL': url}), 201


@app.route('/api/trigger/<otp>')
def api_trigger(otp):
    otp_valid, reason = check_otp(otp)

    ha_url = f"{os.getenv('HA_URL')}/api/services/"
    if os.getenv('HA_AUTOMATION_ID'):
        ha_entity_id = os.getenv('HA_AUTOMATION_ID')
        ha_url = ha_url + 'automation/trigger'
    else:
        ha_entity_id = os.getenv('HA_SCRIPT_ID')
        ha_url = ha_url + 'script/turn_on'
    logging.debug(f"Generated url for home assistant: {ha_url}")

    if otp_valid:
        response = requests.post(f"{ha_url}",
                                 headers={"Authorization": f"Bearer {os.getenv('HA_TOKEN')}",
                                          "Content-Type": "application/json"},
                                 data=json.dumps({"entity_id": ha_entity_id}))
        update_otp(otp, False)
        if response.status_code == 200:
            return jsonify({'Status': 'Access granted!'}), 200
        else:
            logging.error(f"Something went wrong while calling HA: {response.text}")
            return jsonify({'Status': 'Something went wrong!'}), 500
    else:
        return jsonify({'Status': 'Access denied!', 'Reason': reason}), 403


@app.route('/trigger/<otp>')
def trigger(otp):
    return render_template("default.html",
                           url=f"/api/trigger/{otp}", success_result="Status",
                           headline="Press the button to trigger the action!")


@app.route('/generate')
@authorize
def generate():
    return render_template("default.html",
                           url="/generate",  success_result="URL",
                           headline="Press the button to generate a new token!")


def create_connection(db_file):
    """Create a database connection to a SQLite database."""
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        logging.debug(f"Connected to SQLite database: {db_file}")
        return conn
    except sqlite3.Error as e:
        logging.error(e)
    return conn


def create_table():
    """Create a table in the SQLite database."""
    try:
        conn = create_connection(database_file)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                otp TEXT NOT NULL,
                url TEXT NOT NULL,
                valid BOOL NOT NULL,
                created TEXT NOT NULL,
                used TEXT
            );
        ''')
        conn.commit()
        conn.close()
        logging.debug("Table 'data' created successfully.")
    except sqlite3.Error as e:
        logging.error(e)


def insert_otp(otp, url, valid=True):
    """Insert data into the SQLite database."""
    current_time = datetime.now().strftime("%H:%M:%S, %d/%m/%y")
    try:
        conn = create_connection(database_file)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO data (otp, url, valid, created, used)
            VALUES (?, ?, ?, ?, ?);
        ''', (otp, url, valid, current_time, None if valid else current_time))
        conn.commit()
        conn.close()
        logging.debug(f"Data inserted successfully: OTP '{otp}', valid '{valid}'")
    except sqlite3.Error as e:
        logging.error(e)


def update_otp(otp, valid=False):
    """Insert data into the SQLite database."""
    try:
        conn = create_connection(database_file)
        cursor = conn.cursor()
        cursor.execute('''
                    UPDATE data
                    SET valid = ?, used = ?
                    WHERE otp = ?;
                ''', (valid, datetime.now().strftime("%H:%M:%S, %d/%m/%y"), otp))
        conn.commit()
        conn.close()
        logging.debug(f"Data updated successfully: OTP '{otp}' changed to valid '{valid}'")
    except sqlite3.Error as e:
        logging.error(e)


def check_otp(otp):
    try:
        conn = create_connection(database_file)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT otp, valid
            FROM data
            WHERE otp = ?;
        ''', (otp,))
        result = cursor.fetchone()
        conn.close()

        if result is not None:
            if result[1] == 1:
                logging.debug(f"The OTP '{otp}' exists in the database and is valid.")
                return True, None
            else:
                logging.error(f"The OTP '{otp}' exist in the database but is not valid anymore.")
                return False, const.DENIED_REASON_EXPIRED
        else:
            logging.error(f"The OTP '{otp}' does not exist in the database.")
            return False, const.DENIED_REASON_WRONG
    except sqlite3.Error as e:
        logging.error(e)


if __name__ == "__main__":
    try:
        create_table()
    except sqlite3.Error as e:
        logging.error("Could not establish connection to the database.", e)

    app.run(host='0.0.0.0', port=8000)
