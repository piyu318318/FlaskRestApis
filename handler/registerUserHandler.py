import bcrypt

class registerUserHandler:

    def registerUser(self, databaseConnectionObj, username, email, password,secret_key):
        cursor = databaseConnectionObj.cursor()
        password_with_pepper = password + secret_key
        hashed_password = bcrypt.hashpw(password_with_pepper.encode('utf-8'), bcrypt.gensalt())
        cursor.execute("select email from Users where email = %s",(email,))
        emailcheck = cursor.fetchone()
        if emailcheck is None:
            return {"message": "User has registered already using email","status":"200"}

        cursor.execute("select username from Users where username = %s", (username,))
        usernamecheck = cursor.fetchone()
        if usernamecheck is None:
            return {"message": "username is already exist please use another username","status":"200"}

        cursor.execute("INSERT INTO Users (username, email, password) VALUES (%s, %s, %s)", (username, email, hashed_password))
        databaseConnectionObj.commit()
        cursor.close()

        return {"message": "User has registered successfully","status":"200"}
