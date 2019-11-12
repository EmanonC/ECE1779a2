from app import app

app.config['SQLALCHEMY_TRACK_MODIFICATION'] = False



if __name__ == '__main__':
    app.run(host='0.0.0.0', port='5000', debug=True)
