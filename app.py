import eventlet
eventlet.monkey_patch()

import datetime
import os
import secrets
import urllib.parse as urlparse
from functools import wraps
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, current_user, login_required, logout_user
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from sqlalchemy import func, desc, text
import logging
from logging.handlers import RotatingFileHandler

# Create Flask app
app = Flask(__name__)

# --- Database URL Configuration ---
# Handle PostgreSQL URL format from Render/Heroku
def get_database_url():
    database_url = os.environ.get('DATABASE_URL')
    
    if not database_url:
        # Default to SQLite for local development
        return 'sqlite:///database.db'
    
    # If it's already a PostgreSQL URL with postgresql:// prefix
    if database_url.startswith('postgresql://'):
        return database_url
    
    # Convert postgres:// to postgresql:// (for compatibility with SQLAlchemy 1.4+)
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    
    return database_url

# --- Configuration ---
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', 'dev_key_change_in_production_' + secrets.token_hex(16)),
    SQLALCHEMY_DATABASE_URI=get_database_url(),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_ENGINE_OPTIONS={
        'pool_recycle': 280,
        'pool_pre_ping': True,
        'pool_size': 10,
        'max_overflow': 20,
        'pool_timeout': 30,
    } if os.environ.get('DATABASE_URL') else {},  # Only use connection pooling for PostgreSQL
    SESSION_COOKIE_SECURE=os.environ.get('FLASK_ENV') == 'production',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(days=7),
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB max upload
)

# Initialize extensions
db = SQLAlchemy(app)
socketio = SocketIO(app, 
                   cors_allowed_origins="*", 
                   async_mode='eventlet',
                   ping_timeout=60,
                   ping_interval=25,
                   logger=True,
                   engineio_logger=True)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Proxy fix for correct IP detection behind reverse proxy
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# Setup logging
if not app.debug:
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/udota.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Udota startup')

# Log database info
database_url = app.config['SQLALCHEMY_DATABASE_URI']
app.logger.info(f"Database URL: {database_url[:50]}...")
app.logger.info(f"Using PostgreSQL: {'postgresql' in database_url}")

# --- Models ---
class User(UserMixin, db.Model):
    __tablename__ = 'users'  # Changed from 'user' to avoid SQL keyword conflicts
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False, index=True)
    email = db.Column(db.String(150), unique=True, nullable=True)
    password = db.Column(db.String(255), nullable=False)
    lat = db.Column(db.Float, default=0.0)
    lng = db.Column(db.Float, default=0.0)
    is_online = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False)
    points = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    last_login = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    status_message = db.Column(db.String(200), default='')
    
    # Relationships
    messages_sent = db.relationship('Message', backref='author', lazy='dynamic', 
                                   foreign_keys='Message.user_id')
    messages_received = db.relationship('Message', backref='recipient', lazy='dynamic',
                                       foreign_keys='Message.recipient_id')
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'lat': self.lat,
            'lng': self.lng,
            'is_online': self.is_online,
            'is_admin': self.is_admin,
            'points': self.points,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'status_message': self.status_message
        }

class Video(db.Model):
    __tablename__ = 'videos'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text, default='')
    added_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    added_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    duration = db.Column(db.Integer, default=0)  # in seconds
    is_active = db.Column(db.Boolean, default=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'url': self.url,
            'description': self.description,
            'added_at': self.added_at.isoformat() if self.added_at else None
        }

class Message(db.Model):
    __tablename__ = 'messages'
    
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    room = db.Column(db.String(100), default='global')
    is_private = db.Column(db.Boolean, default=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow, index=True)

class AdminLog(db.Model):
    __tablename__ = 'admin_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(200), nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    target_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# --- Helper Functions ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Administrator access required.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def log_admin_action(action, target=None, details=None):
    """Log admin actions for audit trail"""
    if current_user.is_authenticated and current_user.is_admin:
        log = AdminLog(
            action=action,
            admin_id=current_user.id,
            target_id=target.id if target else None,
            details=details
        )
        db.session.add(log)
        db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_request
def update_last_seen():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.datetime.utcnow()
        db.session.commit()

# --- Database Initialization Function ---
def initialize_database():
    """Initialize database tables"""
    with app.app_context():
        try:
            # Test database connection
            db.session.execute(text('SELECT 1'))
            app.logger.info("Database connection successful")
            
            # Create all tables
            db.create_all()
            app.logger.info("Database tables created successfully")
            
            # Check if we need to create a default admin user
            if User.query.count() == 0:
                # Create default admin user if no users exist
                admin_user = User(
                    username=os.environ.get('DEFAULT_ADMIN_USERNAME', 'admin'),
                    email=os.environ.get('DEFAULT_ADMIN_EMAIL', ''),
                    password=generate_password_hash(
                        os.environ.get('DEFAULT_ADMIN_PASSWORD', 'admin123'),
                        method='pbkdf2:sha256'
                    ),
                    is_admin=True,
                    is_online=False
                )
                db.session.add(admin_user)
                db.session.commit()
                app.logger.info("Default admin user created")
            
            # Create indexes for better performance
            if 'postgresql' in app.config['SQLALCHEMY_DATABASE_URI']:
                # Create additional indexes for PostgreSQL
                try:
                    db.session.execute(text('CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages (timestamp DESC)'))
                    db.session.execute(text('CREATE INDEX IF NOT EXISTS idx_users_online ON users (is_online) WHERE is_online = true'))
                    db.session.commit()
                    app.logger.info("PostgreSQL indexes created")
                except Exception as e:
                    app.logger.warning(f"Could not create indexes: {e}")
                
        except Exception as e:
            app.logger.error(f"Error initializing database: {e}")
            # Try to create tables anyway (in case it's a new database)
            try:
                db.create_all()
                app.logger.info("Database tables created on retry")
            except Exception as e2:
                app.logger.error(f"Failed to create tables: {e2}")
                raise

# --- Initialize database on startup ---
initialize_database()

# --- Authentication Routes ---
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        email = request.form.get('email', '').strip().lower()
        
        # Validation
        if not username or not password:
            flash('Username and password are required.', 'error')
            return redirect(url_for('signup'))
        
        if len(username) < 3 or len(username) > 50:
            flash('Username must be between 3 and 50 characters.', 'error')
            return redirect(url_for('signup'))
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return redirect(url_for('signup'))
        
        # Check if username exists (case-insensitive)
        if User.query.filter(func.lower(User.username) == func.lower(username)).first():
            flash('Username already exists.', 'error')
            return redirect(url_for('signup'))
        
        # Check email if provided
        if email and User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return redirect(url_for('signup'))
        
        # Check if this is the first user (make admin)
        is_first_user = User.query.count() == 0
        
        # Create new user
        new_user = User(
            username=username,
            email=email if email else None,
            password=generate_password_hash(password, method='pbkdf2:sha256'),
            is_admin=is_first_user,
            created_at=datetime.datetime.utcnow(),
            last_login=datetime.datetime.utcnow()
        )
        
        try:
            db.session.add(new_user)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error creating user: {e}")
            flash('Error creating account. Please try again.', 'error')
            return redirect(url_for('signup'))
        
        # Log the signup
        if not is_first_user:
            log_admin_action(
                action='user_signup',
                target=new_user,
                details=f'New user registered: {username}'
            )
            socketio.emit('admin_log', {
                'msg': f'New user joined: {username}',
                'timestamp': datetime.datetime.utcnow().isoformat(),
                'type': 'info'
            }, namespace='/', room='admins')
        
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        remember = request.form.get('remember', False)
        
        user = User.query.filter(func.lower(User.username) == func.lower(username)).first()
        
        if user and check_password_hash(user.password, password):
            if user.is_banned:
                flash('This account has been suspended.', 'error')
                return redirect(url_for('login'))
            
            # Update user status
            user.is_online = True
            user.last_login = datetime.datetime.utcnow()
            
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Error updating user status: {e}")
                flash('Database error. Please try again.', 'error')
                return redirect(url_for('login'))
            
            # Log the login
            login_user(user, remember=remember)
            
            # Update session
            session.permanent = True
            
            # Notify about login
            socketio.emit('user_status', {
                'user_id': user.id,
                'username': user.username,
                'status': 'online',
                'timestamp': datetime.datetime.utcnow().isoformat()
            }, broadcast=True)
            
            # Redirect to intended page or dashboard
            next_page = request.args.get('next')
            if next_page and not next_page.startswith('/admin'):
                return redirect(next_page)
            
            return redirect(url_for('index'))
        
        flash('Invalid username or password.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    # Update user status
    current_user.is_online = False
    
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating logout status: {e}")
    
    # Notify about logout
    socketio.emit('user_status', {
        'user_id': current_user.id,
        'username': current_user.username,
        'status': 'offline',
        'timestamp': datetime.datetime.utcnow().isoformat()
    }, broadcast=True)
    
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# --- Main Dashboard & Data ---
@app.route('/')
@login_required
def index():
    """Main dashboard"""
    try:
        # Get online users count
        online_count = User.query.filter_by(is_online=True).count()
        
        # Get latest video
        latest_video = Video.query.filter_by(is_active=True).order_by(Video.added_at.desc()).first()
        
        # Get leaderboard (top 10)
        leaderboard = User.query.filter_by(is_banned=False).order_by(desc(User.points)).limit(10).all()
        
        return render_template('index.html',
                             latest_video=latest_video,
                             online_count=online_count,
                             leaderboard=leaderboard)
    except Exception as e:
        app.logger.error(f"Error loading dashboard: {e}")
        flash('Error loading dashboard. Please try again.', 'error')
        return render_template('index.html',
                             latest_video=None,
                             online_count=0,
                             leaderboard=[])

@app.route('/api/members/locations')
@login_required
def get_members():
    """Get all members with their locations"""
    try:
        users = User.query.filter_by(is_banned=False).all()
        return jsonify([user.to_dict() for user in users])
    except Exception as e:
        app.logger.error(f"Error getting members: {e}")
        return jsonify([]), 500

@app.route('/api/leaderboard')
@login_required
def get_leaderboard():
    """Get leaderboard data"""
    try:
        users = User.query.filter_by(is_banned=False).order_by(desc(User.points)).limit(20).all()
        return jsonify([{
            'username': u.username,
            'points': u.points,
            'rank': i + 1,
            'is_current_user': u.id == current_user.id
        } for i, u in enumerate(users)])
    except Exception as e:
        app.logger.error(f"Error getting leaderboard: {e}")
        return jsonify([]), 500

@app.route('/api/profile/update', methods=['POST'])
@login_required
def update_profile():
    """Update user profile"""
    data = request.get_json()
    
    try:
        if 'status_message' in data:
            current_user.status_message = data['status_message'][:200]
        
        if 'email' in data:
            email = data['email'].strip().lower()
            if email and email != current_user.email:
                if User.query.filter_by(email=email).first():
                    return jsonify({'error': 'Email already in use'}), 400
                current_user.email = email
        
        db.session.commit()
        return jsonify({'message': 'Profile updated', 'user': current_user.to_dict()})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating profile: {e}")
        return jsonify({'error': 'Database error'}), 500

@app.route('/api/reward', methods=['POST'])
@login_required
def reward_user():
    """Reward user for watching content"""
    data = request.get_json()
    
    try:
        seconds_watched = int(data.get('seconds_watched', 0))
        video_id = data.get('video_id')
        
        # Validate input
        if seconds_watched < 10:
            return jsonify({'error': 'Watch at least 10 seconds to earn points'}), 400
        
        # Calculate points (50 points per 10 seconds, capped at 500 per session)
        points_earned = min((seconds_watched // 10) * 50, 500)
        
        # Award points
        current_user.points += points_earned
        
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error awarding points: {e}")
            return jsonify({'error': 'Database error'}), 500
        
        # Log the reward
        log_admin_action(
            action='points_awarded',
            target=current_user,
            details=f'Awarded {points_earned} points for watching video {video_id} ({seconds_watched}s)'
        )
        
        # Notify admin
        socketio.emit('admin_log', {
            'msg': f'💰 {current_user.username} earned {points_earned} points!',
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'type': 'success'
        }, namespace='/', room='admins')
        
        # Notify user
        socketio.emit('points_update', {
            'user_id': current_user.id,
            'username': current_user.username,
            'points': current_user.points,
            'points_earned': points_earned
        }, room=current_user.username)
        
        return jsonify({
            'points_earned': points_earned,
            'total_points': current_user.points,
            'message': f'You earned {points_earned} points!'
        })
        
    except ValueError:
        return jsonify({'error': 'Invalid input data'}), 400
    except Exception as e:
        app.logger.error(f'Error in reward_user: {str(e)}')
        return jsonify({'error': 'Internal server error'}), 500

# --- Agora Token Generation ---
@app.route('/generate-agora-token')
@login_required
def generate_agora_token():
    """Generate Agora token for video calls"""
    import uuid
    
    channel = request.args.get('channel', 'main_room')
    uid = request.args.get('uid', current_user.id)
    
    # Agora configuration (move to environment variables in production)
    APP_ID = os.environ.get('AGORA_APP_ID', 'YOUR_AGORA_APP_ID')
    APP_CERTIFICATE = os.environ.get('AGORA_APP_CERTIFICATE', 'YOUR_AGORA_CERTIFICATE')
    
    if APP_ID == 'YOUR_AGORA_APP_ID' or APP_CERTIFICATE == 'YOUR_AGORA_CERTIFICATE':
        return jsonify({'error': 'Agora not configured'}), 500
    
    try:
        from agora_token_builder import RtcTokenBuilder
        from agora_token_builder.RtcTokenBuilder import RtcRole
        
        # Calculate privilege expire time (24 hours from now)
        expire_time = 3600 * 24
        
        # Generate token
        token = RtcTokenBuilder.buildTokenWithUid(
            APP_ID,
            APP_CERTIFICATE,
            channel,
            int(uid) if uid else 0,
            RtcRole.PUBLISHER,
            expire_time
        )
        
        return jsonify({
            'token': token,
            'app_id': APP_ID,
            'channel': channel,
            'uid': uid,
            'expire_time': expire_time
        })
    except ImportError:
        return jsonify({'error': 'Agora token builder not installed'}), 500
    except Exception as e:
        app.logger.error(f'Error generating Agora token: {e}')
        return jsonify({'error': 'Failed to generate token'}), 500

# --- Admin Portal ---
@app.route('/admin')
@login_required
@admin_required
def admin_portal():
    """Admin dashboard"""
    try:
        # Statistics
        total_users = User.query.count()
        online_users = User.query.filter_by(is_online=True).count()
        banned_users = User.query.filter_by(is_banned=True).count()
        total_points = db.session.query(func.sum(User.points)).scalar() or 0
        
        # Recent videos
        recent_videos = Video.query.order_by(desc(Video.added_at)).limit(10).all()
        
        # Recent logs
        recent_logs = AdminLog.query.order_by(desc(AdminLog.timestamp)).limit(20).all()
        
        # All users for management
        users = User.query.order_by(desc(User.created_at)).all()
        
        return render_template('admin.html',
                             users=users,
                             total_users=total_users,
                             online_users=online_users,
                             banned_users=banned_users,
                             total_points=total_points,
                             recent_videos=recent_videos,
                             recent_logs=recent_logs)
    except Exception as e:
        app.logger.error(f"Error loading admin portal: {e}")
        flash('Error loading admin dashboard.', 'error')
        return render_template('admin.html',
                             users=[],
                             total_users=0,
                             online_users=0,
                             banned_users=0,
                             total_points=0,
                             recent_videos=[],
                             recent_logs=[])

@app.route('/admin/announce', methods=['POST'])
@login_required
@admin_required
def admin_announce():
    """Send global announcement"""
    message = request.form.get('announcement', '').strip()
    
    if not message:
        flash('Announcement cannot be empty.', 'error')
        return redirect(url_for('admin_portal'))
    
    # Broadcast announcement
    socketio.emit('global_announcement', {
        'msg': message,
        'from': current_user.username,
        'timestamp': datetime.datetime.utcnow().isoformat(),
        'type': 'announcement'
    }, broadcast=True)
    
    # Log the action
    log_admin_action(
        action='global_announcement',
        details=message[:200]
    )
    
    flash('Announcement sent!', 'success')
    return redirect(url_for('admin_portal'))

@app.route('/admin/toggle_ban/<int:user_id>')
@login_required
@admin_required
def toggle_ban(user_id):
    """Toggle user ban status"""
    if user_id == current_user.id:
        flash('You cannot ban yourself.', 'error')
        return redirect(url_for('admin_portal'))
    
    try:
        user = User.query.get_or_404(user_id)
        user.is_banned = not user.is_banned
        user.is_online = False if user.is_banned else user.is_online
        
        # If banning, disconnect user
        if user.is_banned:
            socketio.emit('force_logout', {
                'reason': 'Account suspended by administrator'
            }, room=user.username)
        
        db.session.commit()
        
        # Log the action
        action = 'banned' if user.is_banned else 'unbanned'
        log_admin_action(
            action=f'user_{action}',
            target=user,
            details=f'User {action}: {user.username}'
        )
        
        flash(f'User {user.username} has been {action}.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error toggling ban for user {user_id}: {e}")
        flash('Error updating user status.', 'error')
    
    return redirect(url_for('admin_portal'))

@app.route('/admin/reset_points/<int:user_id>')
@login_required
@admin_required
def reset_points(user_id):
    """Reset user points"""
    try:
        user = User.query.get_or_404(user_id)
        old_points = user.points
        user.points = 0
        db.session.commit()
        
        # Log the action
        log_admin_action(
            action='reset_points',
            target=user,
            details=f'Reset points from {old_points} to 0'
        )
        
        # Notify user
        socketio.emit('points_update', {
            'user_id': user.id,
            'username': user.username,
            'points': 0,
            'points_earned': -old_points
        }, room=user.username)
        
        flash(f'Points reset for {user.username}.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error resetting points for user {user_id}: {e}")
        flash('Error resetting points.', 'error')
    
    return redirect(url_for('admin_portal'))

@app.route('/admin/add_video', methods=['POST'])
@login_required
@admin_required
def add_video():
    """Add new video"""
    title = request.form.get('title', '').strip()
    url = request.form.get('url', '').strip()
    description = request.form.get('description', '').strip()
    
    if not title or not url:
        flash('Title and URL are required.', 'error')
        return redirect(url_for('admin_portal'))
    
    # Validate URL
    try:
        result = urlparse.urlparse(url)
        if not all([result.scheme, result.netloc]):
            flash('Invalid URL format.', 'error')
            return redirect(url_for('admin_portal'))
    except:
        flash('Invalid URL format.', 'error')
        return redirect(url_for('admin_portal'))
    
    # Create video
    video = Video(
        title=title,
        url=url,
        description=description,
        added_by=current_user.id,
        is_active=True
    )
    
    try:
        db.session.add(video)
        db.session.commit()
        
        # Log the action
        log_admin_action(
            action='video_added',
            details=f'Added video: {title}'
        )
        
        # Notify users
        socketio.emit('admin_log', {
            'msg': f'🎬 New education module: {title}',
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'type': 'info'
        }, broadcast=True)
        
        flash('Video added successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error adding video: {e}")
        flash('Error adding video.', 'error')
    
    return redirect(url_for('admin_portal'))

@app.route('/admin/delete_video/<int:video_id>')
@login_required
@admin_required
def delete_video(video_id):
    """Delete a video"""
    try:
        video = Video.query.get_or_404(video_id)
        title = video.title
        db.session.delete(video)
        db.session.commit()
        
        # Log the action
        log_admin_action(
            action='video_deleted',
            details=f'Deleted video: {title}'
        )
        
        flash(f'Video "{title}" deleted.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting video {video_id}: {e}")
        flash('Error deleting video.', 'error')
    
    return redirect(url_for('admin_portal'))

# --- SocketIO Events ---
@socketio.on('connect')
def handle_connect():
    """Handle new socket connection"""
    if current_user.is_authenticated:
        # Join user room for private messages
        join_room(current_user.username)
        
        # Join admin room if admin
        if current_user.is_admin:
            join_room('admins')
        
        # Update user status
        current_user.is_online = True
        
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error updating user status on connect: {e}")
        
        # Notify others
        emit('user_connected', {
            'user_id': current_user.id,
            'username': current_user.username,
            'online_count': User.query.filter_by(is_online=True).count(),
            'timestamp': datetime.datetime.utcnow().isoformat()
        }, broadcast=True)
        
        app.logger.info(f'User connected: {current_user.username}')

@socketio.on('disconnect')
def handle_disconnect():
    """Handle socket disconnect"""
    if current_user.is_authenticated:
        # Update user status
        current_user.is_online = False
        
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error updating user status on disconnect: {e}")
        
        # Leave rooms
        leave_room(current_user.username)
        if current_user.is_admin:
            leave_room('admins')
        
        # Notify others
        emit('user_disconnected', {
            'user_id': current_user.id,
            'username': current_user.username,
            'online_count': User.query.filter_by(is_online=True).count(),
            'timestamp': datetime.datetime.utcnow().isoformat()
        }, broadcast=True)
        
        app.logger.info(f'User disconnected: {current_user.username}')

@socketio.on('send_message')
def handle_send_message(data):
    """Handle chat messages"""
    if not current_user.is_authenticated:
        return
    
    msg = data.get('msg', '').strip()
    room = data.get('room', 'global')
    
    if not msg:
        return
    
    # Save message to database
    message = Message(
        content=msg,
        user_id=current_user.id,
        room=room
    )
    
    try:
        db.session.add(message)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error saving message: {e}")
        return
    
    # Broadcast message
    emit('receive_message', {
        'username': current_user.username,
        'msg': msg,
        'room': room,
        'timestamp': datetime.datetime.utcnow().isoformat(),
        'user_id': current_user.id
    }, room=room, broadcast=True)
    
    app.logger.info(f'Chat message from {current_user.username} in {room}: {msg[:50]}...')

@socketio.on('private_message')
def handle_private_message(data):
    """Handle private messages"""
    if not current_user.is_authenticated:
        return
    
    recipient_username = data.get('to', '').strip()
    message = data.get('message', '').strip()
    
    if not recipient_username or not message:
        return
    
    # Find recipient
    recipient = User.query.filter_by(username=recipient_username).first()
    if not recipient or recipient.is_banned:
        emit('error', {'msg': 'User not found or is banned'}, room=current_user.username)
        return
    
    # Save private message
    pm = Message(
        content=message,
        user_id=current_user.id,
        is_private=True,
        recipient_id=recipient.id,
        room=f'private_{min(current_user.id, recipient.id)}_{max(current_user.id, recipient.id)}'
    )
    
    try:
        db.session.add(pm)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error saving private message: {e}")
        emit('error', {'msg': 'Error sending message'}, room=current_user.username)
        return
    
    # Send to recipient
    emit('new_private_msg', {
        'from': current_user.username,
        'from_id': current_user.id,
        'message': message,
        'timestamp': datetime.datetime.utcnow().isoformat()
    }, room=recipient.username)
    
    # Also send to sender for their own UI
    emit('new_private_msg', {
        'from': current_user.username,
        'from_id': current_user.id,
        'to': recipient.username,
        'message': message,
        'timestamp': datetime.datetime.utcnow().isoformat(),
        'is_sent': True
    }, room=current_user.username)

@socketio.on('update_location')
def handle_update_location(data):
    """Update user location"""
    if not current_user.is_authenticated:
        return
    
    try:
        lat = float(data.get('lat', 0))
        lng = float(data.get('lng', 0))
        
        # Validate coordinates
        if -90 <= lat <= 90 and -180 <= lng <= 180:
            current_user.lat = lat
            current_user.lng = lng
            db.session.commit()
            
            # Broadcast location update
            emit('location_update', {
                'user_id': current_user.id,
                'username': current_user.username,
                'lat': lat,
                'lng': lng,
                'timestamp': datetime.datetime.utcnow().isoformat()
            }, broadcast=True)
    except (ValueError, TypeError) as e:
        app.logger.error(f'Invalid location data: {e}')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating location: {e}")

@socketio.on('admin_push_media')
def handle_media_push(data):
    """Admin pushes media to all users"""
    if not current_user.is_authenticated or not current_user.is_admin:
        emit('error', {'msg': 'Unauthorized'}, room=current_user.username)
        return
    
    url = data.get('url', '').strip()
    if not url:
        emit('error', {'msg': 'URL is required'}, room=current_user.username)
        return
    
    # Validate URL
    try:
        result = urlparse.urlparse(url)
        if not all([result.scheme, result.netloc]):
            emit('error', {'msg': 'Invalid URL format'}, room=current_user.username)
            return
    except:
        emit('error', {'msg': 'Invalid URL format'}, room=current_user.username)
        return
    
    # Broadcast media to all users
    emit('sync_media', {
        'url': url,
        'pushed_by': current_user.username,
        'timestamp': datetime.datetime.utcnow().isoformat()
    }, broadcast=True)
    
    # Log the action
    log_admin_action(
        action='media_pushed',
        details=f'Pushed media: {url[:100]}...'
    )
    
    app.logger.info(f'Media pushed by {current_user.username}: {url}')

# --- Error Handlers ---
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('403.html'), 403

# --- Database initialization command ---
@app.cli.command('init-db')
def init_db_command():
    """Initialize the database."""
    initialize_database()
    print('Database initialized.')

@app.cli.command('create-admin')
def create_admin():
    """Create an admin user."""
    from getpass import getpass
    username = input('Username: ')
    password = getpass('Password: ')
    
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if user:
            user.is_admin = True
            user.password = generate_password_hash(password, method='pbkdf2:sha256')
        else:
            user = User(
                username=username,
                password=generate_password_hash(password, method='pbkdf2:sha256'),
                is_admin=True
            )
            db.session.add(user)
        
        db.session.commit()
        print(f'Admin user {username} created/updated.')

# --- Main entry point ---
if __name__ == '__main__':
    # Run the application
    socketio.run(app, 
                 debug=os.environ.get('FLASK_DEBUG', 'False').lower() == 'true',
                 host='0.0.0.0',
                 port=int(os.environ.get('PORT', 5000)),
                 log_output=True)
