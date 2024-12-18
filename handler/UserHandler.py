import pymysql
import bcrypt
import jwt
import datetime
from .configurations import SECRET_KEY, host ,userName , port, userName ,   password , databaseName, accessTokenMinutes, refreshTokenDays


class UserHandler:

    def getDatabaseConnection(self):
        return pymysql.connect(
            host=host,
            port=port,
            user=userName,
            password=password,
            database=databaseName
        )

    def registerUser(self, username, email, password):
        hashedPassword = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        hashedPasswordDecode = hashedPassword.decode('utf-8')
        try:
            conn = self.getDatabaseConnection()
            cursor = conn.cursor()
            cursor.execute("select username from Users where username = %s ",(username,))
            usernameResult = cursor.fetchone()
            if usernameResult:
                return {'message': 'use another username ' ,"status":"200"}

            cursor.execute("select email from Users where email = %s ", (email,))
            emailResult = cursor.fetchone()
            if emailResult:
                return {'message': 'user already registered with this email id  ',"status":"200"}

            cursor.execute("INSERT INTO Users (username, email, password) VALUES (%s, %s, %s)",
                           (username, email, hashedPasswordDecode))
            conn.commit()
            return {'message': 'User registered successfully!',"status":"200"}, 200
        except Exception as e:
            return {'message': 'Error registering user!', 'error': str(e)}, 500
        finally:
            conn.close()

    def loginUser(self, username, password, JWTalgorithm):
        if not username or not password:
            return {'message': 'Username or password missing!', 'status': '400'}, 400

        try:
            conn = self.getDatabaseConnection()
            cursor = conn.cursor()
            cursor.execute("SELECT email FROM Users WHERE username = %s", (username,))
            usernameResult = cursor.fetchone()
            if not usernameResult:
                return {'message': 'User is not registered with this username. Please register!', 'status': '404'}, 404

            cursor.execute("SELECT userid, password FROM Users WHERE username = %s", (username,))
            user = cursor.fetchone()
            if not user or not bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
                return {'message': 'Invalid credentials!', 'status': '401'}, 401

            userid = user[0]

            # Generate tokens
            access_token = jwt.encode(
                {'user_id': userid, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=accessTokenMinutes)},
                SECRET_KEY,
                algorithm=JWTalgorithm
            )
            refresh_token = jwt.encode(
                {'user_id': userid, 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=refreshTokenDays)},
                SECRET_KEY,
                algorithm=JWTalgorithm
            )

            return {
                'message': 'Login successful!',
                'access_token': access_token,
                'refresh_token': refresh_token,
                'status': '200'
            }, 200

        except Exception as e:
            return {'message': 'Error during login!', 'error': str(e), 'status': '500'}, 500

        finally:
            if 'conn' in locals():
                conn.close()

    def getUSerDetails(self, email):
        try:
            conn = self.getDatabaseConnection()
            cursor = conn.cursor()
            cursor.execute("SELECT userid, username, email FROM Users where email = %s", email)
            result = cursor.fetchone()
            if not result:
                return {'message': 'User not Found ',"status":"200"}
            else:
                userid = result[0]
                username = result[1]
                email = result[2]
                return {'message': 'User Found ', 'userid': userid, 'username': username, 'email': email}
        except Exception as e:
            return {'message': 'Error fetching users!', 'error': str(e)}
        finally:
            conn.close()

    def refreshToken(self, token,JWTalgorithm):
        if not token:
            return {'message': 'Refresh token is missing!',"status":"200"},
        try:
            decoded = jwt.decode(token, SECRET_KEY, algorithms=[JWTalgorithm])
            userid = decoded['user_id']
        except Exception as e:
            return {'message': 'Invalid or expired refresh token!'}, 401

        newAccessToken = jwt.encode(
            {'user_id': userid, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=accessTokenMinutes)},
            SECRET_KEY,
            algorithm=JWTalgorithm
        )

        return {'access_token': newAccessToken}, 200
