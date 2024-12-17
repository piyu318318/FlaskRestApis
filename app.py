from flask import Flask, jsonify, request, make_response
import jwt
import datetime
from functools import wraps
import mysql.connector
import configurations
from handler.UserHandler import UserHandler

app = Flask(__name__)
secretKey = configurations.SECRET_KEY
accessTokenMinutes = configurations.accessTokenMinutes
refreshTokenDays = configurations.refreshTokenDays
jwtAlgorithm = configurations.jwtAlgorithm

databaseConnectionObj = None


def databaseConectMethod():
    global databaseConnectionObj
    try:
        databaseConnectionObj = mysql.connector.connect(
            database=configurations.databaseName,
            host=configurations.host,
            port=configurations.port,
            user=configurations.userName,
            password=configurations.password
        )
    except mysql.connector.Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None


@app.route('/myapis/register', methods=['POST'])
def registerAUser():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return make_response({"message": "username, email, and password are required"}, 400)

    if not databaseConnectionObj:
        return make_response({"message": "Database connection failed"}, 500)

    registerUserHandlerObj = UserHandler()
    response = registerUserHandlerObj.registerUser(databaseConnectionObj, username, email, password, secretKey)
    return make_response(response, 200)


@app.route('/myapis/login', methods=['POST'])
def LoginUser():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    print(username,password)

    if not username or not password:
        return make_response({'message': 'username and password are required', 'status': '200'})

    LoginUserHandlerObj = UserHandler()
    response = LoginUserHandlerObj.LoginUser(databaseConnectionObj,username,password,secretKey,jwtAlgorithm, accessTokenMinutes, refreshTokenDays)
    return make_response(response)

if __name__ == '__main__':
    databaseConectMethod()  # will create a connection with database
    app.run(debug=True)
