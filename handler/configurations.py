databaseName = 'FlaskApis'
host = 'localhost'
port = 3306
userName = 'root'
password = 'root123'

#secret key fo password hashing used and access and refresh token to generate
SECRET_KEY = 'e720c4e4ef798f260b3395a09517c4a5672bf0d56d44a34ddcbb3a603d88b493'

accessTokenMinutes = 30  #access token time limit in minutes

refreshTokenDays = 1  #refresh token time limit in days

jwtAlgorithm = "HS256"  #jwt algorithm