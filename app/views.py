from flask import render_template, flash, request, redirect, url_for, session, jsonify
import os
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from app import text_detection, model, db, app
from datetime import timedelta,datetime
import boto3
import requests

# the following four image extensions are allowed
app.config["allowed_img"] = ["png", "jpg", "jpeg", "fig"]
# the maximum image size is 10m
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024

key = boto3.resource('s3')
obj = key.Object('chaoshuai', 'key.txt')
app.secret_key = obj.get()['Body'].read().decode('utf-8')

db.create_all()

httpcnt=0
timestamp=datetime.now()


def allowed_img(filename):
    # a function which determines whether a filename(extension) is allowed
    # str(filename) -> bool
    # If the file extension in 'png', 'jpg', 'jpeg' and 'gif', return True, otherwise return False
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1]
    if ext.lower() in app.config["allowed_img"]:
        return True
    else:
        return False

@app.before_request
def Uploadhttpcounts():
    def makeupload(dt,count,instanceid):
        cloudwatch = boto3.client('cloudwatch',region_name='us-east-1')

        # Put custom metrics
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'httpRequestCount',
                    'Dimensions': [
                        {
                            'Name': 'InstanceID',
                            'Value': instanceid
                        },
                    ],
                    # "Timestamp": '2019-11-10T22:06:00.000Z',
                    "Timestamp": '{}-{}-{}T{}:{}:{}.000Z'.format(dt.year,
                                                                 dt.month,
                                                                 dt.day,
                                                                 dt.hour,
                                                                 dt.minute,
                                                                 dt.second),
                    'Unit': 'Count',
                    'Value': count,
                    'StorageResolution': 60,
                },
            ],
            Namespace='SITE/TRAFFIC'
        )
    global httpcnt
    global timestamp
    dt=datetime.now()
    if timestamp.minute!=dt.minute or timestamp.hour!=dt.hour:
            print('hahahahahaha',httpcnt)
            r = requests.get("http://169.254.169.254/latest/dynamic/instance-identity/document")
            r=r.json()
            instanceid=r.get('instanceId')
            makeupload(dt=dt,count=httpcnt,instanceid=instanceid)
            httpcnt=0
            timestamp=dt
    httpcnt+=1

@app.route('/', methods=["GET", "POST"])
def index():
    # main page
    # If the user has not logged out, redirect to the user page.
    if 'user' in session:
        return redirect(url_for('user'))
    return render_template('index2.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    # registration page
    # On the server side, check whether the username and password are valid or not.
    # username and password must be strings between 2 to 100 characters
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        context = {
            'username_valid': 0,
            'password_valid': 0,
            'pawconfirm_valid': 0,
            'username': username
        }

        flag = False
        if not 2 <= len(username) <= 100:
            context['username_valid'] = 1
            flag = True

        if password != confirm_password:
            context['password_valid'] = 1
            flag = True

        if not 2 <= len(password) <= 100:
            context['password_valid'] = 2
            flag = True

        # users are not allowed to have same username
        dup_user = model.User.query.filter_by(username=username).first()
        if dup_user:
            context['username_valid'] = 2
            flag = True

        if flag:
            return render_template('signup.html', **context)

        # Different users are allowed to have the same password
        # After using salt value for storing passwords, they will look completely different on the server(database)
        # even though they are the same
        password = generate_password_hash(password + username)
        candidate_user = model.User(username=username, password=password)
        db.session.add(candidate_user)
        db.session.commit()

        s3 = boto3.client('s3')
        s3.put_object(
            Bucket='chaoshuai',
            Body='',
            Key=username + '/'
        )
        s3.put_object(
            Bucket='chaoshuai',
            Body='',
            Key=username + '/' + 'original/'
        )
        s3.put_object(
            Bucket='chaoshuai',
            Body='',
            Key=username + '/' + 'processed/'
        )

        # log in
        session['user'] = username
        return redirect(url_for('user'))
    context = {
        'username_valid': -1,
        'password_valid': -1,
        'pawconfirm_valid': -1
    }
    return render_template('signup.html', **context)


@app.route('/login', methods=["GET", "POST"])
def login():
    # login page
    # verify the username and password provided by the user
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        candidate_user = model.User.query.filter_by(username=username).first()
        try:
            candidate_user.username
        except:
            return render_template('login.html', p=1)
        if check_password_hash(candidate_user.password, password + username):
            session['user'] = username
            session.permanent = True
            # after 24 hours, users are required to reenter their usernames and passwords for security purposes
            app.permanent_session_lifetime = timedelta(minutes=1440)
            return redirect(url_for('user', username=username))
        else:
            flash('Invalid username or password')
            return render_template('login.html', p=1)
    else:
        return render_template('login.html')


@app.route('/logout', methods=["GET", "POST"])
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))


@app.route('/user', methods=["GET", "POST"])
def user():
    # if the user are not logged in, redirect to the login page
    if 'user' not in session:
        flash('You are not logged in!')
        return redirect(url_for('index'))
    username = session['user']
    return render_template('user2.html', user=username)


@app.route('/upload', methods=["GET", "POST"])
def upload():
    # if the user are not logged in, redirect to the login page
    if 'user' not in session:
        return redirect(url_for('index'))
    username = session['user']
    # verify the extension of the image which users want to upload
    if request.method == "POST":
        try:
            file = request.files['file']
        except RequestEntityTooLarge:
            return render_template('upload_not_success.html', errorcode=3)
        if request.files:
            if file.filename == "":
                flash("Image must have a filename")
                return render_template('upload_not_success.html', errorcode=1)
            if not allowed_img(file.filename):
                flash("That image extension is not allowed!")
                return render_template('upload_not_success.html', errorcode=2)

            else:
                # use a unique id to mark each image so that images with same name will not overwrite each other
                filename = secure_filename(file.filename)
                uploader = model.User.query.filter_by(username=session['user']).first()
                candidate_file = model.Image(filename=filename)
                candidate_file.uploader = uploader
                db.session.add(candidate_file)
                db.session.commit()

                # do not need to keep the original filename
                useless, ext = filename.rsplit(".", 1)
                name = str(candidate_file.id)
                file_id = candidate_file.id

                # save photos locally

                original_name = 'app/static/original/' + name + '.' + ext
                target_file = 'app/static/processed/' + name + '.' + ext
                file.save(original_name)
                east_location = "app/frozen_east_text_detection.pb"

                # run the text detector and store the new image in the corresponding directory
                try:
                    text_detection.process_image(original_name, east_location, target_file)
                except ValueError:
                    os.remove('app/static/original/' + name + '.' + ext)
                    model.Image.query.filter_by(id=file_id).delete()
                    db.session.commit()
                    return render_template('upload_not_success.html', errorcode=2)
                s3 = boto3.client('s3')
                s3.upload_file(original_name, 'chaoshuai', username + '/original/' + name + '.' + ext)
                s3.upload_file(target_file, 'chaoshuai', username + '/processed/' + name + '.' + ext)
                os.remove('app/static/original/' + name + '.' + ext)
                os.remove('app/static/processed/' + name + '.' + ext)
        return render_template('upload_success.html')
    return render_template('upload2.html')


@app.route("/preview")
def preview():
    # display all the images in the users folder so that each user can only see the images he or she uploaded
    if 'user' not in session:
        flash('You are not logged in!')
        return redirect(url_for('index'))

    current_user = model.User.query.filter_by(username=session['user']).first()
    user_photos = current_user.images
    #  print(user_photo[0].filename)
    hists = {}
    s3 = boto3.client('s3')
    for image in user_photos:
        ext = image.filename.rsplit(".", 1)[1]
        name = str(image.id)
        current_img = name + '.' + ext
        url = s3.generate_presigned_url('get_object',
                                        Params={'Bucket': 'chaoshuai',
                                                'Key': current_user.username + '/original/' + current_img,
                                                })
        hists[url] = [image.filename, current_img]
    return render_template('preview2.html', hists=hists)


@app.route('/fullImg/<img_id>')
def fullImg(img_id):
    # This function allows user to compared two images. One is the photo before text detection while the other is the
    # one after text detection.
    if 'user' not in session:
        flash('You are not logged in!')
        return redirect(url_for('index'))
    s3 = boto3.client('s3')
    current_user = model.User.query.filter_by(username=session['user']).first()
    url_1 = s3.generate_presigned_url('get_object',
                                      Params={'Bucket': 'chaoshuai',
                                              'Key': current_user.username + '/original/' + img_id,
                                              })
    url_2 = s3.generate_presigned_url('get_object',
                                      Params={'Bucket': 'chaoshuai',
                                              'Key': current_user.username + '/processed/' + img_id,
                                              })
    # print(url_2)
    return render_template('full_img2.html', original=url_1, processed=url_2)


@app.route('/delete/<img_id>')
def delete(img_id):
    # remove the image record in the database and the image itself in the s3 bucket
    if 'user' not in session:
        return redirect(url_for('index'))
    image_id = int(img_id.split('.')[0])
    model.Image.query.filter_by(id=image_id).delete()
    db.session.commit()
    s3 = boto3.client('s3')
    username = session['user']
    s3.delete_object(Bucket='chaoshuai', Key=username + '/original/' + img_id)
    s3.delete_object(Bucket='chaoshuai', Key=username + '/processed/' + img_id)
    return redirect(url_for('preview'))


@app.route('/api/register', methods=["POST", "GET"])
def api_register():
    username = request.form.get('username')
    password = request.form.get('password')
    if not isinstance(username, str) or not 2 <= len(username) <= 100:
        return jsonify(message="invalid username!",
                       code=406)

    if not isinstance(username, str) or not 2 <= len(password) <= 100:
        return jsonify(message="invalid password!",
                       code=406)

    dup_user = model.User.query.filter_by(username=username).first()
    if dup_user is not None:
        return jsonify(message="username already exists!",
                       code=406)

    password = generate_password_hash(password + username)
    candidate_user = model.User(username=username, password=password)
    db.session.add(candidate_user)
    db.session.commit()

    s3 = boto3.client('s3')
    s3.put_object(
        Bucket='chaoshuai',
        Body='',
        Key=username + '/'
    )
    s3.put_object(
        Bucket='chaoshuai',
        Body='',
        Key=username + '/' + 'original/'
    )
    s3.put_object(
        Bucket='chaoshuai',
        Body='',
        Key=username + '/' + 'processed/'
    )
    return jsonify(message="user created!",
                   code=201)


@app.route('/api/upload', methods=["POST", "GET"])
def api_upload():
    username = request.form.get('username')
    password = request.form.get('password')
    try:
        file = request.files['file']
    except RequestEntityTooLarge:
        return jsonify(message="file too big!",
                       code=406)
    if not isinstance(username, str) or not 2 <= len(username) <= 100:
        return jsonify(message="invalid username or password!",
                       code=406)
    if not isinstance(username, str) or not 2 <= len(password) <= 100:
        return jsonify(message="invalid username or password!",
                       code=406)
    candidate_user = model.User.query.filter_by(username=username).first()
    if candidate_user is None:
        return jsonify(message="invalid username or password!",
                       code=406)
    if not check_password_hash(candidate_user.password, password + username):
        return jsonify(message="invalid username or password!",
                       code=406)
    if file.filename == "":
        return jsonify(message="Image must have a filename!",
                       code=406)
    if not allowed_img(file.filename):
        return jsonify(message="That image extension is not allowed!",
                       code=406)
    else:
        filename = secure_filename(file.filename)
        uploader = model.User.query.filter_by(username=username).first()
        candidate_file = model.Image(filename=filename)
        candidate_file.uploader = uploader
        db.session.add(candidate_file)
        db.session.commit()
        name, ext = filename.rsplit(".", 1)
        name = str(candidate_file.id)
        file_id = candidate_file.id

        original_name = 'app/static/original/' + name + '.' + ext
        target_file = 'app/static/processed/' + name + '.' + ext
        file.save(os.path.join('app/static/original/', name + '.' + ext))
        east_location = "app/frozen_east_text_detection.pb"

        # run the text detector and store the new image in the corresponding directory
        try:
            text_detection.process_image(original_name, east_location, target_file)
        except ValueError:
            os.remove('app/static/original/' + name + '.' + ext)
            model.Image.query.filter_by(id=file_id).delete()
            db.session.commit()
            return jsonify(message="Invalid file!",
                           code=406)
        s3 = boto3.client('s3')
        s3.upload_file(original_name, 'chaoshuai', username + '/original/' + name + '.' + ext)
        s3.upload_file(target_file, 'chaoshuai', username + '/processed/' + name + '.' + ext)
        os.remove('app/static/original/' + name + '.' + ext)
        os.remove('app/static/processed/' + name + '.' + ext)
        return jsonify(message="Upload success!",
                       code=201)


@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify(message="File too big!",
                   code=413)
