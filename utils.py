from werkzeug.security import (generate_password_hash)
import os
from flask_mail import Message, Mail
mail = Mail()
def allowed_file(filename, allowed_extensions):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in allowed_extensions

def secure_password(password):
    return generate_password_hash(password)    

def send_reset_password_email(user_email, reset_token):
    msg = Message('Reset Your Password', sender=os.getenv('MAIL_USERNAME'), recipients=[user_email])
    msg.body = f'Reset your password: {reset_token}'
    mail.send(msg)
