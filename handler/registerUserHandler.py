import bcrypt

class registerUserHandler:

    def registerUser(self, databaseConnectionObj, username, email, password,secret_key):
        cursor = databaseConnectionObj.cursor()

        cursor.execute("SELECT email FROM Users WHERE email = %s", (email,))
        existingEmail = cursor.fetchone()
        if existingEmail:
            return {"message": "Email already exists","status":"200"}

        cursor.execute("SELECT username FROM Users WHERE username = %s", (username,))
        existingUsername = cursor.fetchone()
        if existingUsername:
            return {"message": "Username is already in used please use another Username", "status": "200"}

        password_with_pepper = password + secret_key
        hashed_password = bcrypt.hashpw(password_with_pepper.encode('utf-8'), bcrypt.gensalt())
        cursor.execute("INSERT INTO Users (username, email, password) VALUES (%s, %s, %s)", (username, email, hashed_password))
        databaseConnectionObj.commit()
        cursor.close()
        return {"message": "User has registered successfully","status":"200"}
