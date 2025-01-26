from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
import hashlib
import time
from datetime import datetime
import pytz
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
import random
from flask import jsonify
print(jsonify)

app = Flask(__name__)
app.config['SECRET_KEY'] = '2s8LFGVDYAgMaPca1L7RTHbZNTg_5Cn3ym23mGmfwFCvXDakh'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

print(jsonify)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'home'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    wallet_balance = db.Column(db.Float, default=0.0)
    wallet_hash = db.Column(db.String(64), unique=True, nullable=False, default='')

class Block:
    def __init__(self, version, previous_hash, merkle_root, timestamp, difficulty, nonce, block_hash):
        self.version = version
        self.previous_hash = previous_hash
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.difficulty = difficulty
        self.nonce = nonce
        self.block_hash = block_hash

class Blockchain:
    def __init__(self):
        self.chain = []

    def add_block(self, block):
        self.chain.append(block)

    def last_block(self):
        return self.chain[-1] if self.chain else None

# Instantiate a global blockchain
blockchain = Blockchain()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=30)])
    submit = SubmitField('Login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash(f"Welcome back, {user.username}!")
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.")
    return redirect(url_for('home'))

@app.route('/faucet', methods=['POST'])
def faucet():
    last_drip_time = session.get('last_drip_time')
    current_time = time.time()

    if last_drip_time and current_time - last_drip_time < 30:
        wait_time = 30 - (current_time - last_drip_time)
        flash(f"Please wait {wait_time:.1f} seconds before using the faucet again.")
        return redirect(url_for('home'))

    session['guest_balance'] = session.get('guest_balance', 0) + 1
    session['last_drip_time'] = current_time
    flash(f"1 coin has been added to your wallet. Your new balance is {session['guest_balance']} coins.")
    return redirect(url_for('home'))

@app.route('/generate_hash', methods=['POST'])
def generate_hash():
    text_to_hash = request.form.get('text_to_hash')
    if not text_to_hash:
        flash("Please provide text to hash.")
        return redirect(url_for('home'))

    sha256_hash = hashlib.sha256(text_to_hash.encode()).hexdigest()
    flash(f"SHA256 Hash: {sha256_hash}")
    return redirect(url_for('home'))

@app.route('/mine', methods=['POST'])
def mine():
    est = pytz.timezone('US/Eastern')
    last_block = blockchain.last_block()

    previous_hash = last_block.block_hash if last_block else "0" * 64
    block = {
        "version": "1.0",
        "previous_hash": previous_hash,
        "merkle_root": hashlib.sha256("example_transactions".encode()).hexdigest(),
        "timestamp": datetime.now(est).strftime('%Y-%m-%d %H:%M:%S'),
        "difficulty": session.get("difficulty", 1),
        "nonce": 0
    }

    difficulty_string = "0" * block["difficulty"]
    while True:
        block_string = f"{block['version']}{block['previous_hash']}{block['merkle_root']}{block['timestamp']}{difficulty_string}{block['nonce']}"
        block_hash = hashlib.sha256(block_string.encode()).hexdigest()

        if block_hash.startswith(difficulty_string):
            # Block successfully mined
            new_block = Block(
                block['version'], block['previous_hash'], block['merkle_root'],
                block['timestamp'], block['difficulty'], block['nonce'], block_hash
            )
            blockchain.add_block(new_block)

            session['guest_balance'] = session.get('guest_balance', 0) + 50  # Reward 50 coins
            session['previous_hash'] = block_hash

            return jsonify({"success": True, "message": f"Block mined! Hash: {block_hash}", "block_hash": block_hash})

        block['nonce'] += 1


    # Save the block hash to the session
    session['block_hash'] = block_hash

    # Display the block hash
    flash(f"Block hash: {block_hash}")

    # Check if the block is successfully mined
    if block_hash.startswith(difficulty_string):
        flash(f"Congratulations! Block mined successfully. Hash: {block_hash}")

        # Update session for guest wallet mining
        session['previous_hash'] = block_hash
        session['merkle_root'] = hashlib.sha256(block_hash.encode()).hexdigest()
        session['guest_balance'] = session.get('guest_balance', 0) + 50  # Reward 50 coins
        return redirect(url_for('home'))

    # If not mined, update nonce for user to try again
    session['nonce'] = block['nonce']
    flash("Keep trying! The block is not yet mined.")
    return redirect(url_for('home'))


@app.route('/adjust_difficulty', methods=['POST'])
def adjust_difficulty():
    action = request.form.get("action")
    current_difficulty = session.get("difficulty", 1)

    if action == "increase":
        session["difficulty"] = current_difficulty + 1
    elif action == "decrease" and current_difficulty > 1:
        session["difficulty"] = current_difficulty - 1

    flash(f"Difficulty adjusted to: {session['difficulty']}")
    return redirect(url_for('home'))

@app.route('/')
def home():
    guest_wallet_hash = hashlib.sha256("guest".encode()).hexdigest()
    guest_balance = session.get("guest_balance", 0)
    
    return render_template(
        'index.html',
        previous_hash=session.get("previous_hash", "0" * 64),
        merkle_root=session.get("merkle_root", "0" * 64),
        nonce=session.get("nonce", 0),
        difficulty=session.get("difficulty", 1),
        timestamp=datetime.now(pytz.timezone('US/Eastern')).strftime('%Y-%m-%d %H:%M:%S'),
        wallet_hash=guest_wallet_hash,
        wallet_balance=guest_balance,
        user_logged_in=current_user.is_authenticated
    )

@app.route('/transact')
def transact():
    return render_template('transact.html')

@app.route('/play')
def play():
    return render_template('play.html')

@app.route('/learn')
def learn():
    return render_template('learn.html')

@app.route('/transactions')
def transactions():
    return render_template('transactions.html')

@app.route('/block_explorer')
def block_explorer():
    return render_template('block_explorer.html', blockchain=blockchain.chain)


@app.route('/clear-session')
def clear_session():
    session.clear()
    flash("Session cleared.")
    return redirect(url_for('home'))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)


















