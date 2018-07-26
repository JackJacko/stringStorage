from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.strStorageDB
Users = db["Users"]

def verify_pw(usr, pwd):
    h_pwd = Users.find({"Username":usr})[0]["Password"]

    if bcrypt.hashpw(pwd.encode('utf8'), h_pwd) == h_pwd:
        return True
    else:
        return False

def check_username(usr):
    if Users.find({"Username":usr},{"Username":1}).count() > 0:
        return True
    else:
        return False

def check_tokens(usr):
    tokenNum = Users.find({"Username":usr})[0]["Tokens"]
    return tokenNum

class Register(Resource):
    def post(self):
        # get posted data
        Data = request.get_json()
        # check data for missing input
        if 'Username' not in Data or 'Password' not in Data:
            retErr = {
                "Message": "An error happened.",
                "Status code": 301,
                "Error": "Input data is missing."
            }
            return jsonify(retErr)
        # assign data to variables
        usr = Data['Username']
        pwd = Data['Password']
        # check if username is in use
        if check_username(usr):
            retErr = {
                "Message": "An error happened.",
                "Status code": 302,
                "Error": "Username is already taken."
            }
            return jsonify(retErr)
        # hash the password
        h_pwd = bcrypt.hashpw(pwd.encode('utf8'), bcrypt.gensalt())
        # store username and hashed password
        Users.insert_one({
            "Username": usr,
            "Password": h_pwd,
            "Sentence": "",
            "Tokens": 10
        })
        # confirm successful registration
        retJson = {
            "Status code": 200,
            "Message": "Your registration was successful."
        }
        return jsonify(retJson)

class Store(Resource):
    def post(self):
        # get posted data
        Data = request.get_json()
        # check data for missing input
        if 'Username' not in Data or 'Password' not in Data or 'Sentence' not in Data:
            retErr = {
                "Message": "An error happened.",
                "Status code": 301,
                "Error": "Input data is missing."
            }
            return jsonify(retErr)
        # assign data to variables
        usr = Data['Username']
        pwd = Data['Password']
        str = Data['Sentence']
        # check if username is registered
        if not check_username(usr):
            retErr = {
                "Message": "An error happened.",
                "Status code": 303,
                "Error": "Username not present in database. Please register."
            }
            return jsonify(retErr)
        # check if password is correct
        if not verify_pw(usr, pwd):
            retErr = {
                "Message": "An error happened.",
                "Status code": 304,
                "Error": "Wrong password."
            }
            return jsonify(retErr)
        # check token amount
        tkn = check_tokens(usr)
        if tkn <= 0:
            retErr = {
                "Message": "An error happened.",
                "Status code": 305,
                "Error": "Insufficient tokens."
            }
            return jsonify(retErr)
        # store the sentence, update tokens and return success
        Users.update_one({
            "Username": usr
        }, {
            "$set": {
                "Sentence": str,
                "Tokens": tkn - 1
            }
        })
        retJson = {
            "Status code": 200,
            "Message": "Sentence stored successfully.",
            "Tokens remaining": check_tokens(usr)
        }
        return jsonify(retJson)

class Get(Resource):
    def post(self):
        # get posted data
        Data = request.get_json()
        # check data for missing input
        if 'Username' not in Data or 'Password' not in Data:
            retErr = {
                "Message": "An error happened.",
                "Status code": 301,
                "Error": "Input data is missing."
            }
            return jsonify(retErr)
        # assign data to variables
        usr = Data['Username']
        pwd = Data['Password']
        # check if username is registered
        if not check_username(usr):
            retErr = {
                "Message": "An error happened.",
                "Status code": 303,
                "Error": "Username not present in database. Please register."
            }
            return jsonify(retErr)
        # check if password is correct
        if not verify_pw(usr, pwd):
            retErr = {
                "Message": "An error happened.",
                "Status code": 304,
                "Error": "Wrong password."
            }
            return jsonify(retErr)
        # check token amount
        tkn = check_tokens(usr)
        if tkn <= 0:
            retErr = {
                "Message": "An error happened.",
                "Status code": 305,
                "Error": "Insufficient tokens."
            }
            return jsonify(retErr)
        # get the sentence, update tokens and return success
        sentence = Users.find({"Username": usr})[0]['Sentence']
        Users.update_one({
            "Username": usr
        }, {
            "$set": {
                "Tokens": tkn - 1
            }
        })
        retJson = {
            "Status code": 200,
            "Stored sentence": sentence,
            "Tokens remaining": check_tokens(usr)
        }
        return jsonify(retJson)

api.add_resource(Register, "/signup")
api.add_resource(Store, "/store")
api.add_resource(Get, "/get")

if __name__=="__main__":
    app.run(host ='0.0.0.0', debug = True)
