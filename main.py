from pyad import *
import flask
from pymongo import MongoClient
import certifi
import json
import socket
from flask import Flask, request
from datetime import datetime,time,timedelta
import sublist3r
import threading
import time
import requests

app = Flask(_name_)

client=MongoClient('mongodb+srv://cirius:MVA1IzOr8GCYoSv8@cluster0.53e13.mongodb.net/?retryWrites=true&w=majority',tlsCAFile=certifi.where())

#Domain Name in explore functions

def exploreusers(ide):
    q = adquery.ADQuery()
    db=client.db
    conn=db.users
    q.execute_query(
        attributes = ["name","userprincipalname","memberof"],
        where_clause = "objectClass = '*'",
        base_dn = "CN=Users, DC=lab01, DC=local"
    )
    if(ide!=1):
        for row in q.get_results():
            if(row["userprincipalname"] is not None):
                a=[]
                if(row["memberof"] is not None):
                    for i in row["memberof"]:
                        a.append(i)
                a=json.dumps(a)
                row["memberof"]=a
                if(conn.find_one(row["userprincipalname"]) is None):
                    conn.insert_one(row)
    else:
        up=[]
        for row in q.get_results():
            if(row["userprincipalname"] is not None):
                a=[]
                if(row["memberof"] is not None):
                    for i in row["memberof"]:
                        a.append(i)
                a=json.dumps(a)
                row["memberof"]=a
                up.append(row)
        conn.insert_many(up)        
        
def exploredevices(ide):
    q = adquery.ADQuery()
    db=client.db
    conn=db.computers
    q.execute_query(
        attributes = ["dnshostname","cn","operatingsystem","operatingsystemhotfix","operatingsystemservicepack","operatingsystemversion","memberof"],
        where_clause = "objectClass = '*'",
        base_dn = "CN=Computers, DC=lab01, DC=local"
    )
    if(ide!=1):
        data=q.get_results()
        for row in data:
            if(row["dnshostname"] is None):
                continue
            print(type(row))
            a=[]
            if(row["memberof"] is not None):
                for i in row["memberof"]:
                    a.append(i)
            a=json.dumps(a)
            row["memberof"]=a
            ip=""
            if(row["dnshostname"] is not None):
                ip=socket.gethostbyname(row["dnshostname"])
            row["ip"]=ip
            if(conn.find(row["dnshostname"]) is None):
                conn.insert_one(row)
    else:  
        up=[]
        data=q.get_results()
        for row in data:
            if(row["dnshostname"] is None):
                continue
            print(type(row))
            a=[]
            if(row["memberof"] is not None):
                for i in row["memberof"]:
                    a.append(i)
            a=json.dumps(a)
            row["memberof"]=a
            ip=""
            if(row["dnshostname"] is not None):
                ip=socket.gethostbyname(row["dnshostname"])
            row["ip"]=ip
            up.append(row)
            print(row["ip"],row["operatingsystem"])
        conn.insert_many(up)
