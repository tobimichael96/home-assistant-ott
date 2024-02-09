import json
import logging
import os
import random
import sqlite3

import requests
from flask import Flask, redirect, url_for, render_template, flash, session, current_app, request, abort, jsonify
# from flask_sqlalchemy import SQLAlchemy
# from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user


import constants as const

app = Flask(__name__)
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)


@app.route('/')
def home():
    return redirect("https://www.tobiasmichael.de/", code=302)


# @app.route('/authorize/google')
# def oauth2_authorize():
#     if not current_user.is_anonymous:
#         return redirect(url_for('index'))
#
#     # generate a random string for the state parameter
#     session['oauth2_state'] = secrets.token_urlsafe(16)
#
#     'google': {
#         'client_id': os.environ.get('GOOGLE_CLIENT_ID'),
#         'client_secret': os.environ.get('GOOGLE_CLIENT_SECRET'),
#         'authorize_url': 'https://accounts.google.com/o/oauth2/auth',
#         'token_url': 'https://accounts.google.com/o/oauth2/token',
#         'userinfo': {
#             'url': 'https://www.googleapis.com/oauth2/v3/userinfo',
#             'email': lambda json: json['email'],
#         },
#         'scopes': ['https://www.googleapis.com/auth/userinfo.email'],
#     },
#
#     # create a query string with all the OAuth2 parameters
#     qs = urlencode({
#         'client_id': provider_data['client_id'],
#         'redirect_uri': url_for('oauth2_callback', provider=provider,
#                                 _external=True),
#         'response_type': 'code',
#         'scope': ' '.join(provider_data['scopes']),
#         'state': session['oauth2_state'],
#     })
#
#     # redirect the user to the OAuth2 provider authorization URL
#     return redirect(provider_data['authorize_url'] + '?' + qs)

@app.route('/clear/<token>')
def clear_database(token):
    if token == os.getenv("ACCESS_TOKEN"):
        try:
            conn = create_connection(database_file)
            cursor = conn.cursor()
            cursor.execute('''
                DELETE FROM data;
            ''')
            conn.commit()
            conn.close()
            logging.info("All data in the table 'data' has been deleted.")
            return jsonify({'Status': 'Clearing the database worked!'}), 200
        except sqlite3.Error as e:
            logging.error(e)
            return jsonify({'Status': 'Something went wrong!'}), 500
    else:
        return jsonify({'Status': 'Access denied!'}), 403


@app.route('/generate/<token>')
def generate_link_route(token):
    if token == os.getenv("ACCESS_TOKEN"):
        otp = ''.join([str(random.randint(0, 9)) for _ in range(16)])
        insert_otp(otp)

        return jsonify({
                           'URL': f"{'https://' + os.getenv('BASE_URL') if os.getenv('BASE_URL') is not None else request.host_url}open/{otp}"}), 201
    else:
        return jsonify({'Status': 'Access denied!'}), 403


@app.route('/open/<otp>')
def use_link(otp):
    result, reason = check_otp(otp)

    if result:
        api_call_req = requests.post("https://ha.tmem.de/api/services/automation/trigger",
                                     headers={"Authorization": f"Bearer {os.getenv('HA_TOKEN')}",
                                              "Content-Type": "application/json"},
                                     data=json.dumps({"entity_id": f"automation.{os.getenv('HA_AUTOMATION_ID')}"}))
        if api_call_req.status_code != 200:
            logging.error(api_call_req.json())
            return jsonify({'Status': 'Something went wrong!'}), 500
        update_otp(otp, False)
        return jsonify({'Status': 'Access granted!'}), 200
    else:
        return jsonify({'Status': 'Access denied!', 'Reason': reason}), 403


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
                value TEXT NOT NULL,
                valid BOOL NOT NULL
            );
        ''')
        conn.commit()
        conn.close()
        logging.debug("Table 'data' created successfully.")
    except sqlite3.Error as e:
        logging.error(e)


def insert_otp(value, valid=True):
    """Insert data into the SQLite database."""
    try:
        conn = create_connection(database_file)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO data (value, valid)
            VALUES (?, ?);
        ''', (value, valid))
        conn.commit()
        conn.close()
        logging.debug(f"Data inserted successfully: OTP '{value}', Valid '{valid}'")
    except sqlite3.Error as e:
        logging.error(e)


def update_otp(value, valid=False):
    """Insert data into the SQLite database."""
    try:
        conn = create_connection(database_file)
        cursor = conn.cursor()
        cursor.execute('''
                    UPDATE data
                    SET valid = ?
                    WHERE value = ?;
                ''', (valid, value))
        conn.commit()
        conn.close()
        logging.debug(f"Data updated successfully: OTP '{value}' changed to valid '{valid}'")
    except sqlite3.Error as e:
        logging.error(e)


def check_otp(value):
    """Check if the provided value matches any entry in the SQLite database."""
    try:
        conn = create_connection(database_file)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT value, valid
            FROM data
            WHERE value = ?;
        ''', (value,))
        result = cursor.fetchone()
        conn.close()

        if result is not None:
            if result[1] == 1:
                logging.debug(f"The OTP '{value}' exists in the database and is valid.")
                return True, None
            else:
                logging.error(f"The OTP '{value}' exist in the database but is not valid anymore.")
                return False, const.DENIED_REASON_EXPIRED
        else:
            logging.error(f"The OTP '{value}' does not exist in the database.")
            return False, const.DENIED_REASON_WRONG
    except sqlite3.Error as e:
        logging.error(e)


def generate_link():
    return "Link"


if __name__ == "__main__":
    database_file = '/data/database.db'
    try:
        create_table()
    except sqlite3.Error as e:
        logging.error("Could not establish connection to the database.", e)

    app.run(host='0.0.0.0', port=8000)
