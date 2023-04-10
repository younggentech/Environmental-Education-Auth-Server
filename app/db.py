# https://flask.palletsprojects.com/en/2.2.x/tutorial/database/
# The only difference is the use of MySQL instead of SQLite
import os

import dotenv
import mysql.connector as connector

import click
from flask import current_app, g
from flask.cli import with_appcontext

dotenv.load_dotenv()


def get_db():
    """
    A function returns a `g` instance which will be used for each request
    """
    if 'db' not in g:
        g.connection = connector.connect(user=os.environ['DATABASE_USER'],
                                         password=os.environ['DATABASE_PASSWORD'],
                                         host=os.environ['DATABASE_HOST'],
                                         port=os.environ['DATABASE_PORT'],
                                         database=os.environ['DATABASE_NAME']
                                         )
        g.db = g.connection.cursor(dictionary=True)
    return g.db, g.connection


def close_db(e=None):
    """Closing db"""
    db = g.pop('db', None)

    if db is not None:
        db.close()


def init_db():
    """Initiate the databased based on schema"""
    db, connection = get_db()
    with current_app.open_resource('schema.sql') as f:
        for query in f.read().decode('utf8').split(';'):
            db.execute(query)


@click.command('init-db')
@with_appcontext
def init_db_command():
    """Adding init db to app context"""
    """Clear the existing data and create new tables."""
    init_db()
    click.echo('Initialized the database.')


def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
