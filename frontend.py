from flask import Flask, jsonify, request, render_template,redirect,make_response, redirect, url_for
from pymongo import MongoClient
from bson import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
import datetime
import hashlib, binascii, os
import random,string
import jinja2

def hash_password(password):
    """Hash a password for storing."""
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'),
                                salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    to_store=(salt + pwdhash).decode('ascii')
    db=client.db
    to_update=db.first
    to_update.update({},{"$set": {'password':to_store}})
    return


def verify_password(stored_password, provided_password):
    """Verify a stored password against one provided by user"""
    salt = stored_password[:64]
    stored_password = stored_password[64:]
    pwdhash = hashlib.pbkdf2_hmac('sha512',
                                  provided_password.encode('utf-8'),
                                  salt.encode('ascii'),
                                  100000)
    pwdhash = binascii.hexlify(pwdhash).decode('ascii')
    return pwdhash == stored_password

app=Flask(__name__)
app.config['SECRET_KEY']='Th1s1ss3cr3t' # isko hide krna hai

client=MongoClient('mongodb+srv://cirius:MVA1IzOr8GCYoSv8@cluster0.53e13.mongodb.net/db?retryWrites=true&w=majority')

def token_required(f): # ISME BHI HTML HI RETURN KRWAAYA HAI, SINCE YE BHI EK PAGE HI HAI
   @wraps(f)
   def decorator(*args, **kwargs):
       token=None
       if 'x-access-tokens' in request.cookies:
           token=request.cookies['x-access-tokens']
           print(token)
       if not token:
            return render_template('login.html',error="Token not provided, login to get your token.")
            #return jsonify({"Message":"Token not provided."})
       try:
            data=jwt.decode(token,app.config['SECRET_KEY'])
       except:
           return render_template('login.html',error="Token is invalid, login to get your token.")
           return jsonify({'message': 'token is invalid'})

       return f(*args, **kwargs)
   return decorator

def get_os_piechart():
    db=client.db
    all_computers=db.computers
    temp_list={}
    for all in all_computers.find():
        if all['operatingsystem'] in temp_list.keys():
            temp_list[all['operatingsystem']]+=1
        else:
            temp_list[all['operatingsystem']]=1
    return temp_list

def get_hist_users():
    db=client.db
    all_users=db.users
    temp_list={}
    for all in all_users.find():
        del all['_id']
        temp_char_list=all['memberof'].split(',')
        for word in temp_char_list:
            print(word)
            if '=' in word:
                ind=word.index('=')
                if word[ind-1]=='N':
                    if word[ind+1:] in temp_list.keys():
                        print("HERE")
                        temp_list[word[ind+1:]]+=1
                    else:
                        temp_list[word[ind+1:]]=1
                    #print(word[ind+1:])
    return temp_list
