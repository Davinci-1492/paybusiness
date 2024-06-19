from flask import Flask, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from config import Config
import paypalrestsdk
from flask_apscheduler import APScheduler
from datetime import datetime, timedelta
from flask_login import LoginManager
from flask_mail import Mail
from authlib.integrations.flask_client import OAuth
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)
oauth = OAuth(app)
bcrypt = Bcrypt(app)

google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    refresh_token_url=None,
    redirect_uri=None,
    client_kwargs={'scope': 'openid profile email'},
)

paypalrestsdk.configure({
    "mode": "sandbox",
    "client_id": app.config['PAYPAL_CLIENT_ID'],
    "client_secret": app.config['PAYPAL_CLIENT_SECRET']
})

scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

def renew_invoices():
    with app.app_context():
        from models import Customer
        customers = Customer.query.all()
        for customer in customers:
            if customer.next_invoice_date <= datetime.utcnow():
                customer.next_invoice_date = datetime.utcnow() + timedelta(days=30)
                db.session.commit()
                send_invoice(customer.id)

scheduler.add_job(id='renew_invoices', func=renew_invoices, trigger='interval', days=1)

# Import routes after the app and db have been initialized
from routes import *

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
