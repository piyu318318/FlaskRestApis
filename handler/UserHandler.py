import bcrypt
import jwt
import datetime
import json

class UserHandler:

    def registerUser(self, databaseConnectionObj, username, email, password, secretKey):
        cursor = databaseConnectionObj.cursor()

        cursor.execute("SELECT email FROM Users WHERE email = %s", (email,))
        existingEmail = cursor.fetchone()
        if existingEmail:
            return {"message": "Email already exists", "status": "200"}

        cursor.execute("SELECT username FROM Users WHERE username = %s", (username,))
        existingUsername = cursor.fetchone()
        if existingUsername:
            return {"message": "Username is already in used please use another Username", "status": "200"}

        password_with_pepper = password + secretKey
        hashedPassword = bcrypt.hashpw(password_with_pepper.encode('utf-8'), bcrypt.gensalt())
        cursor.execute("INSERT INTO Users (username, email, password) VALUES (%s, %s, %s)",
                       (username, email, hashedPassword))
        databaseConnectionObj.commit()
        cursor.close()
        return {"message": "User has registered successfully", "status": "200"}

    def LoginUser(self, databaseConnectionObj, username, password, jwtsecretKey, jwtAlgorithm, accessTokenMinutes,
                  refreshTokenDays):
        cursor = databaseConnectionObj.cursor()
        cursor.execute("select username, password from Users where username = %s", (username,))
        userRecord = cursor.fetchone()
        if userRecord is None:
            return {"message": "Invalid Username", "status": "200"}

        databaseUsername, databaseHashedPassword = userRecord
        passwordWithKey = password + jwtsecretKey

        if not bcrypt.checkpw(passwordWithKey.encode('utf-8'), databaseHashedPassword.encode('utf-8')):
            return {"message": "Invalid Password", "status": "200"}

        accessTokenPayload = {"username": databaseUsername,
                              "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=accessTokenMinutes)}
        refreshTokenPayload = {"username": databaseUsername,
                               "exp": datetime.datetime.utcnow() + datetime.timedelta(days=refreshTokenDays)}

        accessToken = jwt.encode(accessTokenPayload, jwtsecretKey, algorithm=jwtAlgorithm)
        refreshToken = jwt.encode(refreshTokenPayload, jwtsecretKey, algorithm=jwtAlgorithm)

        cursor.close()
        return {
            "message": "Login successful",
            "status": "200",
            "access_token": accessToken,
            "refresh_token": refreshToken
        }

    def getUserDetails(self, databaseConnectionObj, username):
        cursor = databaseConnectionObj.cursor()
        cursor.execute("SELECT * FROM Users WHERE username = %s", (username,))
        userDetails = cursor.fetchall()
        if not userDetails:
            return {"message": "User does not exist", "status": "404"}
        cursor.close()
        return {"message": "User found", "data": userDetails, "status": "200"}
