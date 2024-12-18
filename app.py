from flask import Flask, jsonify, request , make_response
from handler.UserHandler import UserHandler
import pymysql
from handler import configurations
from functools import wraps
import jwt

app = Flask(__name__)
app.config['SECRET_KEY'] = configurations.SECRET_KEY
JWTalgorithm = configurations.jwtAlgorithm

def getDatabaseConnection():
    return pymysql.connect(
        host=configurations.host,
        port=configurations.port,
        user=configurations.userName,
        password=configurations.password,
        database=configurations.databaseName
    )


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            token = token.split(" ")[1]
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=[JWTalgorithm])
            request.user_id = decoded['user_id']
        except Exception as e:
            return jsonify({'message': 'Invalid or expired token!'}), 401
        return f(*args, **kwargs)
    return decorated


# Routes
@app.route('/myapis/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    if not username or not email or not password:
        return make_response({'message': 'All fields are required!','status':'200'})
    userHandlerObj = UserHandler()
    response = userHandlerObj.registerUser(username, email, password)
    return make_response(response)

@app.route('/myapis/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return make_response({'message': 'username and password both fields are required!', 'status':'200'})
    userHandlerObj = UserHandler()
    response = userHandlerObj.loginUser(username, password, JWTalgorithm)
    return make_response(response)


@app.route('/myapis/users', methods=['GET'])
@token_required
def getUsers():
    data = request.json
    email = data.get('email')
    if not email :
        return make_response({'message': 'email  field is  required!', 'status':'200'})
    userHandlerObj = UserHandler()
    response = userHandlerObj.getUSerDetails(email)
    return make_response(response)


@app.route('/refresh', methods=['POST'])
def refresh():
    data = request.json
    token = data.get('refresh_token')
    UserHandlerObj = UserHandler()
    response = UserHandlerObj.refreshToken(token, JWTalgorithm)
    return response


if __name__ == '__main__':
    app.run(debug=True)
