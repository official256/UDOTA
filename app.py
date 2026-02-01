import eventlet
eventlet.monkey_patch()

import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, current_user, login_required, logout_user
from flask_socketio import SocketIO, emit, join_room
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- Configuration ---
app.config.update(
    SECRET_KEY='dev_key_123',
    SQLALCHEMY_DATABASE_URI='sqlite:///database.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
)

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    lat = db.Column(db.Float, default=0.0)
    lng = db.Column(db.Float, default=0.0)
    is_online = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False) 
    points = db.Column(db.Integer, default=0)

class Video(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    url = db.Column(db.String(500))

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- Authentication ---

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            flash("Username exists")
            return redirect(url_for('signup'))
        
        is_first = User.query.count() == 0
        new_user = User(
            username=username, 
            password=generate_password_hash(password, method='pbkdf2:sha256'), 
            is_admin=is_first
        )
        db.session.add(new_user)
        db.session.commit()
        socketio.emit('admin_log', {'msg': f"New user joined: {username}"})
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and check_password_hash(user.password, request.form.get('password')):
            if user.is_banned:
                flash("This account has been suspended.")
                return redirect(url_for('login'))
            login_user(user, remember=True)
            user.is_online = True
            db.session.commit()
            return redirect(url_for('index'))
        flash("Invalid credentials")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    current_user.is_online = False
    db.session.commit()
    logout_user()
    return redirect(url_for('login'))

# --- Main Dashboard & Data ---

@app.route('/')
@login_required
def index():
    latest_video = Video.query.order_by(Video.id.desc()).first()
    return render_template('index.html', latest_video=latest_video)

@app.route('/get_members')
@login_required
def get_members():
    users = User.query.all()
    return jsonify([{"name": u.username, "lat": u.lat, "lng": u.lng, "active": u.is_online, "points": u.points, "is_banned": u.is_banned} for u in users])

@app.route('/get_leaderboard')
@login_required
def get_leaderboard():
    users = User.query.order_by(User.points.desc()).limit(10).all()
    return jsonify([{"username": u.username, "points": u.points} for u in users])

@app.route('/reward', methods=['POST'])
@login_required
def reward_user():
    data = request.get_json()
    if data.get('seconds_watched', 0) >= 10:
        current_user.points += 50
        db.session.commit()
        socketio.emit('admin_log', {'msg': f"💰 {current_user.username} earned points!"})
        return jsonify({"new_balance": current_user.points})
    return jsonify({"error": "Watch longer!"}), 400

# --- Admin Portal Management ---

@app.route('/admin')
@login_required
def admin_portal():
    if not current_user.is_admin:
        flash("Unauthorized.")
        return redirect(url_for('index'))
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/admin/announce', methods=['POST'])
@login_required
def admin_announce():
    if not current_user.is_admin: return "Unauthorized", 403
    message = request.form.get('announcement')
    socketio.emit('global_announcement', {'msg': message})
    return redirect(url_for('admin_portal'))

@app.route('/admin/toggle_ban/<int:user_id>')
@login_required
def toggle_ban(user_id):
    if not current_user.is_admin: return "Unauthorized", 403
    user = db.session.get(User, user_id)
    if user and user.id != current_user.id:
        user.is_banned = not user.is_banned
        db.session.commit()
    return redirect(url_for('admin_portal'))

@app.route('/admin/reset_points/<int:user_id>')
@login_required
def reset_points(user_id):
    if not current_user.is_admin: return "Unauthorized", 403
    user = db.session.get(User, user_id)
    if user:
        user.points = 0
        db.session.commit()
    return redirect(url_for('admin_portal'))

@app.route('/admin/add_video', methods=['POST'])
@login_required
def add_video():
    if not current_user.is_admin: return "Unauthorized", 403
    new_video = Video(title=request.form.get('title'), url=request.form.get('url'))
    db.session.add(new_video)
    db.session.commit()
    socketio.emit('admin_log', {'msg': f"New education module: {new_video.title}"})
    return redirect(url_for('admin_portal'))

# --- SocketIO Events ---

@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        current_user.is_online = True
        db.session.commit()
        join_room(current_user.username)
        emit('status_change', {'user': current_user.username, 'status': 'online'}, broadcast=True)

@socketio.on('send_message')
def handle_send_message(data):
    emit('receive_message', {'username': current_user.username, 'msg': data['msg']}, broadcast=True)

@socketio.on('private_message')
def handle_private_message(data):
    recipient = data.get('recipient')
    emit('new_private_msg', {'sender': current_user.username, 'message': data.get('msg')}, room=recipient)

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        current_user.is_online = False
        db.session.commit()
        emit('status_change', {'user': current_user.username, 'status': 'offline'}, broadcast=True)
@socketio.on('admin_push_media')
def handle_media_push(data):
    # Only let admins broadcast
    if current_user.is_admin:
        # Broadcast the URL to every connected client
        emit('sync_media', {'url': data['url']}, broadcast=True)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True, port=5000)
