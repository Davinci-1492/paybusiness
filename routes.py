from flask import render_template, url_for, flash, redirect, request, session
from app import app, db, bcrypt, mail, google
from forms import AddCustomerForm, RegistrationForm, LoginForm, RequestResetForm, ResetPasswordForm
from models import User, Customer, Payment
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Message
import paypalrestsdk
from datetime import datetime, timedelta

@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/account')
@login_required
def account():
    return render_template('account.html', title='Account')

@app.route('/dashboard')
@login_required
def dashboard():
    # This is where you will gather statistics for the dashboard
    return render_template('dashboard.html', title='Dashboard')

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='noreply@demo.com',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_reset_email(user)
            flash('An email has been sent with instructions to reset your password.', 'info')
            return redirect(url_for('login'))
        else:
            flash('No account found with that email.', 'warning')
    return render_template('reset_request.html', title='Reset Password', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)

@app.route('/login/google')
def login_google():
    redirect_uri = url_for('authorized', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/login/google/authorized')
def authorized():
    token = google.authorize_access_token()
    if token is None:
        flash('Access denied: reason={} error={}'.format(
            request.args['error_reason'],
            request.args['error_description']
        ))
        return redirect(url_for('login'))
    resp = google.get('userinfo')
    userinfo = resp.json()
    email = userinfo['email']
    user = User.query.filter_by(email=email).first()
    if user is None:
        user = User(email=email)
        db.session.add(user)
        db.session.commit()
    login_user(user)
    return redirect(url_for('dashboard'))

@app.route('/edit_customer/<int:customer_id>', methods=['GET', 'POST'])
@login_required
def edit_customer(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    if request.method == 'POST':
        customer.name = request.form['name']
        customer.email = request.form['email']
        customer.phone_number = request.form['phone_number']
        customer.address = request.form['address']
        customer.monthly_amount = request.form['monthly_amount']
        db.session.commit()
        flash('Customer updated successfully', 'success')
        return redirect(url_for('dashboard'))
    return render_template('edit_customer.html', customer=customer)

@app.route('/send_invoice/<int:customer_id>', methods=['GET'])
@login_required
def send_invoice(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    payment = paypalrestsdk.Payment({
        "intent": "sale",
        "payer": {
            "payment_method": "paypal"
        },
        "redirect_urls": {
            "return_url": url_for('payment_executed', customer_id=customer.id, _external=True),
            "cancel_url": url_for('dashboard', _external=True)
        },
        "transactions": [{
            "item_list": {
                "items": [{
                    "name": "Monthly Subscription",
                    "sku": "001",
                    "price": str(customer.monthly_amount),
                    "currency": "USD",
                    "quantity": 1
                }]
            },
            "amount": {
                "total": str(customer.monthly_amount),
                "currency": "USD"
            },
            "description": "Monthly subscription for {}".format(customer.name)
        }]
    })

    if payment.create():
        for link in payment.links:
            if link.rel == "approval_url":
                approval_url = str(link.href)
                return redirect(approval_url)
    else:
        flash('Error while creating payment')
        return redirect(url_for('dashboard'))

@app.route('/payment_executed/<int:customer_id>', methods=['GET'])
def payment_executed(customer_id):
    payment_id = request.args.get('paymentId')
    payer_id = request.args.get('PayerID')

    payment = paypalrestsdk.Payment.find(payment_id)

    if payment.execute({"payer_id": payer_id}):
        payment_record = Payment(customer_id=customer_id, amount=payment.transactions[0].amount.total, status='Completed')
        db.session.add(payment_record)
        db.session.commit()
        flash('Payment successful')
        customer = Customer.query.get_or_404(customer_id)
        customer.next_invoice_date = datetime.utcnow() + timedelta(days=30)
        db.session.commit()
    else:
        flash('Payment failed')

    return redirect(url_for('dashboard'))

# Sidebar Navigation Routes
@app.route("/add_customer", methods=['GET', 'POST'])
@login_required
def add_customer():
    form = AddCustomerForm()
    if form.validate_on_submit():
        existing_customer = Customer.query.filter_by(email=form.email.data).first()
        if existing_customer:
            flash('Email address already exists.', 'danger')
        else:
            customer = Customer(
                name=form.name.data, 
                email=form.email.data, 
                phone_number=form.phone_number.data, 
                address=form.address.data, 
                monthly_amount=form.monthly_amount.data
            )
            db.session.add(customer)
            db.session.commit()
            flash('Customer added successfully', 'success')
            return redirect(url_for('show_recent_customers'))
    return render_template('add_customer.html', title='Add Customer', form=form)

# Additional routes here...

@app.route("/show_recent_customers")
@login_required
def show_recent_customers():
    customers = Customer.query.all()
    customer_data = []
    for customer in customers:
        recent_payment = Payment.query.filter_by(customer_id=customer.id).order_by(Payment.date.desc()).first()
        payment_history = Payment.query.filter_by(customer_id=customer.id).all()
        customer_data.append({
            'customer': customer,
            'recent_payment': recent_payment,
            'payment_history': payment_history
        })
    return render_template('show_recent_customers.html', title='Recent Customers', customers=customer_data)



@app.route('/show_coming_invoices')
@login_required
def show_coming_invoices():
    invoices = Payment.query.filter(Payment.status == 'Due').order_by(Payment.date.asc()).all()
    return render_template('show_coming_invoices.html', invoices=invoices)

@app.route('/show_paid_invoices')
@login_required
def show_paid_invoices():
    invoices = Payment.query.filter(Payment.status == 'Completed').order_by(Payment.date.desc()).all()
    return render_template('show_paid_invoices.html', invoices=invoices)
