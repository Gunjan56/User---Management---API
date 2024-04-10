from flask import Blueprint, jsonify, request
from flask_jwt_extended import create_access_token
from werkzeug.security import check_password_hash, generate_password_hash
from app.model import db, User
from app.main.validators.validators import Validators
from app.utils import allowed_file,send_reset_password_email
from app.main.Error.error_response import error_response
from app.main.Error.success_response import success_response
import os
import base64
from werkzeug.utils import secure_filename


auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.json
    validation_result = Validators.check_user_required_fields(data)
    if validation_result["status"] == 200:
        if 'profile_picture' in request.files:
            profile_picture = request.files['profile_picture']
            if profile_picture and allowed_file(profile_picture.filename):
                filename = secure_filename(profile_picture.filename)
                profile_picture.save(os.path.join(os.getenv('UPLOAD_FOLDER'), filename))
                data['profile_picture'] = filename

        user = User.query.filter_by(username=data.get('username'), email=data.get('email')).first()

        if user:
            return error_response(400,"User already registered")

        hashed_password = generate_password_hash(data.get('password'))

        new_user = User(
            username=data.get('username'),
            email=data.get('email'),
            password=hashed_password,
            profile_picture=data.get('profile_picture')
        )

        db.session.add(new_user)
        db.session.commit()

        return success_response(201, 'success', "User registered successfully")
    else:
        return jsonify(validation_result), validation_result["status"]

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    validation_result = Validators.check_login_required_fields(data)
    if validation_result["status"] == 200:
        user = User.query.filter_by(username=data.get('username')).first()

        if not user or not check_password_hash(user.password, data['password']):
            error_response(401, 'Invalid username or password')

        access_token = create_access_token(identity=user.id)

        return jsonify(access_token=access_token), 200
    else:
        return jsonify(validation_result), validation_result["status"]

@auth_bp.route('/forgot_password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data['email']
    user = User.query.filter_by(email=email).first()
    
    if user:
        reset_token = base64.b64encode(email.encode('utf-8')).decode('utf-8')

        send_reset_password_email(email, reset_token)

        return success_response(201, 'success', 'Reset password link sent to your email')
    else:
        return error_response(404, 'User not found')
    

@auth_bp.route('/reset_password/<token>', methods=['POST'])
def reset_password(token):
    data = request.get_json()
    new_password = data['new_password']
    confirm_password = data['confirm_password']
    
    if new_password != confirm_password:
        return error_response(400, 'New password and confirm password do not match')

    email = base64.b64decode(token).decode('utf-8')
    
    user = User.query.filter_by(email=email).first()
    if user:
        user.password = generate_password_hash(new_password)
        db.session.commit()
        return success_response(200, 'success','Password reset successfully')
    else:
        return error_response(404, 'User not found')
