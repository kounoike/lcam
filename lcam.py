#!env python
# coding: utf-8

import datetime
import re

import bcrypt
import click
import pymongo
from urlparse import urlparse


def get_hash(password):
    '''Returns bcrypted hash for password'''
    hashed = bcrypt.hashpw(password.encode("ascii"), bcrypt.gensalt(10))
    return hashed


def conn_mongo(mongouri):
    '''Connect to mongo db'''
    client = pymongo.MongoClient(mongouri)
    db = client.get_default_database()
    return db


def exists_user(db, username):
    user = db.users.find_one({"username": username})
    return user is not None


def exists_email(db, email):
    user = db.users.find_one({"email": email})
    return user is not None


def validate_username(ctx, param, value):
    '''Validate rule for username'''
    value = value.strip()
    if not re.match(r"^[^\.][a-z0-9_\.]+[^\.]$", value, flags=re.IGNORECASE):
        raise click.BadParameter("Bad Username")
    return value


@click.group()
def cli():
    '''lcam - Let's Chat Account Manager'''
    pass


@cli.command()
@click.option('--username', '-u', required=True, callback=validate_username)
@click.option('--email', '-e', prompt=True)
@click.option('--password', '-p', prompt=True, hide_input=True, confirmation_prompt=True)
@click.option('--displayname', '-d', prompt=True)
@click.option('--firstname', '-f', prompt=True)
@click.option('--lastname', '-l', prompt=True)
@click.option('--mongouri', default='mongodb://localhost/letschat')
def adduser(username, email, password, displayname, firstname, lastname, mongouri):
    '''Add user'''
    db = conn_mongo(mongouri)
    if exists_user(db, username):
        click.echo("User %s already exists." % username)
        return
    if exists_email(db, email):
        click.echo("Email[%s] must be unique." % email)
        return

    if click.confirm("Do you want to add user %s?" % username):
        obj = {
            "username": username,
            "password": get_hash(password),
            "displayname": displayname,
            "firstname": firstname,
            "lastname": lastname,
            "email": email,
            "provider": "local",
            "messages": [],
            "rooms": [],
            "joined": datetime.datetime.utcnow()
        }
        db.users.insert(obj)
        click.echo("User %s added." % username)
    else:
        click.echo("add user canceled.")


@cli.command()
@click.option('--username', '-u', required=True)
@click.option('--mongouri', default='mongodb://localhost/letschat')
def deluser(username, mongouri):
    '''Delete user'''
    db = conn_mongo(mongouri)
    if exists_user(db, username):
        if click.confirm("Do you want to remove user %s?" % username):
            db.users.remove({"username": username})
            click.echo("User %s removed." % username)
        else:
            click.echo("Delete canceled.")
    else:
        click.echo("User %s not found." % username)


@cli.command()
@click.option('--mongouri', default='mongodb://localhost/letschat')
def listuser(mongouri):
    '''List users'''
    db = conn_mongo(mongouri)
    users = db.users.find({"provider": "local"})

    click.echo("There are %d users." % users.count())

    for u in users:
        click.echo(u)
    click.echo("List user")


@cli.command()
@click.option('--username', '-u', required=True)
@click.option('--password', '-p', prompt=True, hide_input=True, confirmation_prompt=True)
@click.option('--mongouri', default='mongodb://localhost/letschat')
def password(username, password, mongouri):
    '''Change password'''
    db = conn_mongo(mongouri)
    if exists_user(db, username):
        if click.confirm("Do you want to change passsword for %s?" % username):
            db.users.update({"username": username}, {"$set": {"password": get_hash(password)}})
            click.echo("User %s's password was changed." % username)
        else:
            click.echo("Delete canceled.")
    else:
        click.echo("User %s not found." % username)


if __name__ == "__main__":
    cli()
