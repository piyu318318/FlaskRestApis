from flask import Flask, jsonify, request, make_response
import jwt
import datetime
from functools import wraps
import mysql.connector
import configurations
from handler.registerUserHandler import registerUserHandler

app = Flask(__name__)
secret_key = app.config['SECRET_KEY'] = 'e720c4e4ef798f260b3395a09517c4a5672bf0d56d44a34ddcbb3a603d88b493'

databaseConnectionObj = None  # Initialize the global variable outside the function

def databaseConectMethod():
    global databaseConnectionObj  # Reference the global variable
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

    registerUserHandlerObj = registerUserHandler()
    response = registerUserHandlerObj.registerUser(databaseConnectionObj, username, email, password,secret_key)
    return make_response(response, 200)

if __name__ == '__main__':
    databaseConectMethod()  # Establish the DB connection before starting the app
    app.run(debug=True)
