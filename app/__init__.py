from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import boto3

dia = 'mysql'
dri = 'pymysql'
username = 'admin'
password = 'password'
host = 'ece1779.csoa2umt5i5j.us-east-1.rds.amazonaws.com'
port = '3306'
database = 'ece1779_a2'

# SQLALCHEMY_DATABASE_URI = "{}+{}://{}:{}@{}:{}/{}?charset=utf8".format(dia, dri, username, password, host, port, database)
SQLALCHEMY_DATABASE_URI = "{}+{}://{}:{}@{}:{}/{}?charset=utf8".format(dia, dri, username, password, host, port, database)

app = Flask(__name__, template_folder='templates')
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
db = SQLAlchemy(app)
from app import views
