from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from authlib.integrations.flask_client import OAuth
import os
import random

# Allow HTTP for OAuth in development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', '5f36a0d8e2b8f9c1d4e7a2b5c8d1e4f7a0b3c6d9e2f5a8b1')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///voting.db')
if app.config['SQLALCHEMY_DATABASE_URI'].startswith("postgres://"):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'

# OAuth Configuration
app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID', 'YOUR_GOOGLE_CLIENT_ID_HERE')
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET', 'YOUR_GOOGLE_CLIENT_SECRET_HERE')

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',  # This is only needed if using openid to fetch user info
    client_kwargs={'scope': 'email profile'},
)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    prn = db.Column(db.String(13), unique=True, nullable=False) # 13 digit PRN
    name = db.Column(db.String(100))
    mobile = db.Column(db.String(15))
    email = db.Column(db.String(120)) # Added email field
    mother_name = db.Column(db.String(100))
    class_name = db.Column(db.String(50))
    division = db.Column(db.String(10))
    year = db.Column(db.String(20)) # e.g. "2023-2024" or "First Year"
    password = db.Column(db.String(255)) # Increased length for security/compatibility
    role = db.Column(db.String(10), default='student') # 'student' or 'admin'
    has_voted = db.Column(db.Boolean, default=False)

class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    class_name = db.Column(db.String(50))
    division = db.Column(db.String(10))
    photo_url = db.Column(db.String(200)) # Placeholder for image path
    votes = db.Column(db.Integer, default=0)

class ElectionState(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    is_active = db.Column(db.Boolean, default=False)
    is_finished = db.Column(db.Boolean, default=False)
    winner_declared = db.Column(db.Boolean, default=False)

# Initialize DB
def init_db():
    with app.app_context():
        db.create_all()
        
        # Ensure Admin exists with specific credentials
        admin_email = 'admin@dyp.edu'
        admin = User.query.filter_by(role='admin').first()
        
        if not admin:
            # Create new admin
            admin = User(prn='admin', email=admin_email, name='Administrator', password='admin123', role='admin')
            db.session.add(admin)
        else:
            # Update existing admin credentials to ensure they match
            admin.email = admin_email
            admin.password = 'admin123'
            
        # Create initial election state
        if not ElectionState.query.first():
            state = ElectionState(is_active=False, is_finished=False)
            db.session.add(state)
            
        db.session.commit()

# Routes

@app.route('/')
def index():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('vote_page'))
    return render_template('login.html')

@app.route('/api/signup', methods=['POST'])
def api_signup():
    data = request.get_json()
    prn = data.get('prn')
    name = data.get('name')
    email = data.get('email')
    mobile = data.get('mobile')
    mother_name = data.get('mother_name')
    password = data.get('password') 
    
    # 1. Check if user exists (by PRN)
    existing_user = User.query.filter_by(prn=prn).first()
    
    if existing_user:
        # 2. If User exists and has email -> Already Registered
        if existing_user.email:
             return jsonify({'success': False, 'message': 'Account already exists for this PRN. Please Login.'})
             
        # 3. If User exists (Pre-uploaded) -> Verify Details
        # We check if provided details match the record (Case insensitive for strings)
        # Note: In real world, might be lenient, but here we check strictly as requested
        
        db_name = existing_user.name.lower().replace(" ", "") if existing_user.name else ""
        input_name = name.lower().replace(" ", "") if name else ""
        
        db_mother = existing_user.mother_name.lower().replace(" ", "") if existing_user.mother_name else ""
        input_mother = mother_name.lower().replace(" ", "") if mother_name else ""
        
        db_mobile = str(existing_user.mobile).strip() if existing_user.mobile else ""
        input_mobile = str(mobile).strip() if mobile else ""

        # Verification Logic
        # If dataset has missing fields, we might skip checking them? 
        # Assuming dataset is complete based on upload_dataset logic.
        
        if db_name != input_name or db_mobile != input_mobile or db_mother != input_mother:
             return jsonify({'success': False, 'message': 'Details do not match University Records. Please check PRN, Name, Mobile, and Mother Name.'})
             
        # 4. Verification Successful -> Update Record
        existing_user.email = email
        existing_user.password = password
        # existing_user.name = name # Keep official name or update? Keep official.
        
        db.session.commit()
        session['user_id'] = existing_user.id
        return jsonify({'success': True, 'redirect': url_for('profile_page')})
        
    else:
        # 5. User NOT in dataset
        # Option A: Reject (Strict)
        return jsonify({'success': False, 'message': 'PRN not found in University Database. Please contact Administrator.'})
        
        # Option B: Allow Open Signup (Legacy) - Commented out for now
        # new_user = User(prn=prn, name=name, email=email, mobile=mobile, mother_name=mother_name, password=password, role='student')
        # db.session.add(new_user)
        # db.session.commit()
        # session['user_id'] = new_user.id
        # return jsonify({'success': True, 'redirect': url_for('profile_page')})

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    email = data.get('email')
    
    # Admin Login Check
    if data.get('is_admin'):
        password = data.get('password')
        user = User.query.filter_by(email=email).first()
        if user and user.role == 'admin' and user.password == password:
            session['user_id'] = user.id
            return jsonify({'success': True, 'redirect': url_for('admin_dashboard')})
        else:
            return jsonify({'success': False, 'message': 'Invalid Admin Credentials'})
            
    # Student Login (Firebase Verified)
    # If we are here, Firebase has already verified the email/password
    user = User.query.filter_by(email=email).first()
    
    if user:
        if user.role == 'admin':
             # Admin shouldn't login via student form, but if they do...
             return jsonify({'success': False, 'message': 'Please use Admin Login'})
             
        session['user_id'] = user.id
        return jsonify({'success': True, 'redirect': url_for('profile_page')})
    else:
        return jsonify({'success': False, 'message': 'User not found in database. Please Signup first.'})

@app.route('/api/google_login', methods=['POST'])
def api_google_login():
    data = request.get_json()
    email = data.get('email')
    name = data.get('name')
    
    user = User.query.filter_by(email=email).first()
    
    if user:
        # Login existing user
        session['user_id'] = user.id
        if user.role == 'admin':
            return jsonify({'success': True, 'redirect': url_for('admin_dashboard')})
        return jsonify({'success': True, 'redirect': url_for('profile_page')})
    else:
        # Auto-Signup new user via Google
        import uuid
        # Generate a temporary PRN since we don't have it from Google
        temp_prn = "G-" + str(uuid.uuid4().int)[:10] 
        
        new_user = User(prn=temp_prn, name=name, email=email, role='student')
        db.session.add(new_user)
        db.session.commit()
        
        session['user_id'] = new_user.id
        return jsonify({'success': True, 'redirect': url_for('profile_page')})

@app.route('/api/verify_profile', methods=['POST'])
def verify_profile():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    current_user = User.query.get(session['user_id'])
    if not current_user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
        
    data = request.get_json()
    prn = data.get('prn')
    name = data.get('name')
    mobile = data.get('mobile')
    mother_name = data.get('mother_name')
    
    # Check if PRN exists in dataset
    dataset_user = User.query.filter_by(prn=prn).first()
    
    if not dataset_user:
        return jsonify({'success': False, 'message': 'PRN not found in University Records.'})
        
    # If the user is verifying against themselves (already merged/verified)
    if dataset_user.id == current_user.id:
         return jsonify({'success': True, 'redirect': url_for('vote_page')})
         
    # If dataset user is already claimed by someone else (has email set)
    if dataset_user.email and dataset_user.email != current_user.email:
        return jsonify({'success': False, 'message': 'This PRN is already registered/claimed.'})
        
    # Verify Details
    def normalize(s): return str(s).lower().replace(" ", "") if s else ""
    
    # Note: We compare against dataset_user (official record)
    if (normalize(dataset_user.name) != normalize(name) or 
        normalize(dataset_user.mobile) != normalize(mobile) or 
        normalize(dataset_user.mother_name) != normalize(mother_name)):
        return jsonify({'success': False, 'message': 'Details do not match University Records. Please check all fields.'})
        
    # MERGE: Transfer Academic Info to Current User and Delete Dataset Row
    try:
        # Cache info from dataset row
        class_name = dataset_user.class_name
        division = dataset_user.division
        year = dataset_user.year
        real_prn = dataset_user.prn
        real_mobile = dataset_user.mobile
        real_mother = dataset_user.mother_name
        
        # Delete dataset row to free up PRN (constraint)
        db.session.delete(dataset_user)
        db.session.flush() 
        
        # Update current user with official info
        current_user.prn = real_prn
        current_user.class_name = class_name
        current_user.division = division
        current_user.year = year
        current_user.mobile = real_mobile
        current_user.mother_name = real_mother
        
        db.session.commit()
        return jsonify({'success': True, 'redirect': url_for('vote_page')})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error during verification: {str(e)}'})

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == 'admin' and password == 'admin123':
            admin = User.query.filter_by(role='admin').first()
            if not admin:
                admin = User(prn='ADMIN', name='Administrator', email='admin@dyp.edu', role='admin', password='admin_password')
                db.session.add(admin)
                db.session.commit()
            
            session['user_id'] = admin.id
            return redirect(url_for('admin_dashboard'))
        return "Invalid Credentials", 401
            
    return """
    <form method="post" style="text-align:center; margin-top:50px;">
        <h2>Admin Login</h2>
        <input type="text" name="username" placeholder="Username" required><br><br>
        <input type="password" name="password" placeholder="Password" required><br><br>
        <button type="submit">Login</button>
    </form>
    """

@app.route('/login', methods=['POST'])
def login():
    # Legacy route - keeping just in case, but redirecting to index or handling simple posts
    return redirect(url_for('index'))

@app.route('/google/login')
def google_login():
    redirect_uri = url_for('google_authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/google/authorize')
def google_authorize():
    try:
        token = google.authorize_access_token()
        resp = google.get('userinfo')
        user_info = resp.json()
        email = user_info['email']
        name = user_info.get('name', 'Google User')
        
        # Check if user exists
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Login existing user
            session['user_id'] = user.id
            session['google_token'] = token
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('vote_page'))
        else:
            # Auto-Signup new user via Google
            # We don't have PRN from Google, so we might need to ask for it later
            # For now, let's generate a placeholder or redirect to a completion page
            # OR just create the user. Let's create the user.
            
            # Use email prefix as temp PRN or similar unique ID if PRN is required unique
            # But PRN should be valid. 
            # Ideally we redirect to a "Complete Profile" page to ask for PRN.
            # For this task, let's assume we just create the user.
            
            # NOTE: If PRN is unique, we can't just make one up safely.
            # But let's use a random one for now to satisfy the flow.
            # Better approach: Redirect to signup page with pre-filled email/name
            
            # Let's create the user directly for smooth UX as requested "Google Authentication Button"
            # typically implies one-click entry.
            
            import uuid
            temp_prn = "G-" + str(uuid.uuid4().int)[:10] 
            
            new_user = User(prn=temp_prn, name=name, email=email, role='student')
            db.session.add(new_user)
            db.session.commit()
            
            session['user_id'] = new_user.id
            session['google_token'] = token
            flash('Account created via Google! Please update your PRN in profile if needed.')
            return redirect(url_for('vote_page'))
            
    except Exception as e:
        flash(f'Authentication failed: {str(e)}')
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/profile')
def profile_page():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    user = User.query.get(session['user_id'])
    if not user:
         session.pop('user_id', None)
         return redirect(url_for('index'))
         
    return render_template('profile.html', user=user)

@app.route('/vote')
def vote_page():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    user = User.query.get(session['user_id'])
    if not user:
         session.pop('user_id', None)
         return redirect(url_for('index'))

    state = ElectionState.query.first()
    
    if state.is_finished or state.winner_declared:
        return redirect(url_for('results_page'))

    candidates = Candidate.query.all()
    return render_template('vote.html', user=user, candidates=candidates, election_active=state.is_active)

@app.route('/submit_vote', methods=['POST'])
def submit_vote():
    if 'user_id' not in session:
        return redirect(url_for('index'))
        
    user = User.query.get(session['user_id'])
    state = ElectionState.query.first()
    
    if not state.is_active:
        flash("Election is not active!")
        return redirect(url_for('vote_page'))
        
    if user.has_voted:
        flash("You have already voted!")
        return redirect(url_for('vote_page'))
        
    candidate_id = request.form['candidate_id']
    candidate = Candidate.query.get(candidate_id)
    
    if candidate:
        candidate.votes += 1
        user.has_voted = True
        db.session.commit()
        flash("Vote cast successfully!")
        return render_template('thank_you.html')
    
    return redirect(url_for('vote_page'))

# Admin Routes
@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    user = User.query.get(session['user_id'])
    if user.role != 'admin':
        return redirect(url_for('vote_page'))
        
    candidates = Candidate.query.order_by(Candidate.votes.desc(), Candidate.name).all()
    state = ElectionState.query.first()
    
    # Get uploaded datasets summary
    # Group by Class, Division, Year and count students
    datasets = db.session.query(
        User.class_name, 
        User.division, 
        User.year, 
        db.func.count(User.id).label('count')
    ).filter_by(role='student').group_by(User.class_name, User.division, User.year).all()
    
    return render_template('admin.html', candidates=candidates, state=state, datasets=datasets)

import csv
import io

# ... existing imports ...

@app.route('/admin/upload_dataset', methods=['POST'])
def upload_dataset():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    user = User.query.get(session['user_id'])
    if user.role != 'admin':
        return redirect(url_for('vote_page'))

    class_name = request.form.get('class_name')
    division = request.form.get('division')
    year = request.form.get('year')
    
    if not class_name or not division or not year:
        flash('Class, Division and Year are required!', 'danger')
        return redirect(url_for('admin_dashboard'))

    if 'file' not in request.files:
        flash('No file part')
        return redirect(url_for('admin_dashboard'))
        
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('admin_dashboard'))
        
    if file:
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
        csv_input = csv.reader(stream)
        
        # Expected CSV Format: PRN, Name, Mobile, Mother Name
        # Skip header if exists? Let's assume header exists if first row not numeric
        
        added_count = 0
        error_count = 0
        
        for i, row in enumerate(csv_input):
            if i == 0 and "prn" in row[0].lower():
                continue # Skip header
                
            if len(row) < 4:
                continue
                
            prn = row[0].strip()
            name = row[1].strip()
            mobile = row[2].strip()
            mother_name = row[3].strip()
            
            if User.query.filter_by(prn=prn).first():
                error_count += 1 # Already exists
                continue
                
            new_student = User(prn=prn, name=name, mobile=mobile, mother_name=mother_name, class_name=class_name, division=division, year=year, role='student')
            db.session.add(new_student)
            added_count += 1
            
        db.session.commit()
        flash(f'Dataset uploaded for {class_name}-{division} ({year}): {added_count} students added. {error_count} duplicates skipped.')
        
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_dataset', methods=['POST'])
def delete_dataset():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    user = User.query.get(session['user_id'])
    if user.role != 'admin':
        return redirect(url_for('vote_page'))
        
    class_name = request.form.get('class_name')
    division = request.form.get('division')
    year = request.form.get('year')
    
    if not class_name or not division or not year:
        flash('Missing dataset identifiers!', 'error')
        return redirect(url_for('admin_dashboard'))
        
    # Delete students matching the criteria
    deleted_count = User.query.filter_by(
        role='student',
        class_name=class_name,
        division=division,
        year=year
    ).delete()
    
    db.session.commit()
    flash(f'Dataset deleted! Removed {deleted_count} students from {class_name}-{division} ({year}).')
    return redirect(url_for('admin_dashboard'))

# ... existing routes ...
@app.route('/admin/add_candidate', methods=['POST'])
def add_candidate():
    name = request.form['name']
    class_name = request.form['class_name']
    division = request.form['division']
    
    photo_url = "https://via.placeholder.com/100"
    
    if 'photo' in request.files:
        file = request.files['photo']
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            # Add random prefix to avoid overwrites
            filename = f"{random.randint(1000, 9999)}_{filename}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            photo_url = url_for('static', filename=f'uploads/{filename}')
            
    new_candidate = Candidate(name=name, class_name=class_name, division=division, photo_url=photo_url)
    db.session.add(new_candidate)
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_candidate/<int:candidate_id>', methods=['POST'])
def delete_candidate(candidate_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))
    user = User.query.get(session['user_id'])
    if user.role != 'admin':
        return redirect(url_for('vote_page'))
        
    candidate = Candidate.query.get(candidate_id)
    if candidate:
        db.session.delete(candidate)
        db.session.commit()
        flash('Candidate deleted successfully!')
    else:
        flash('Candidate not found!')
        
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/toggle_election', methods=['POST'])
def toggle_election():
    action = request.form['action'] # 'start', 'stop', 'reset'
    state = ElectionState.query.first()
    
    if action == 'start':
        state.is_active = True
        state.is_finished = False
        state.winner_declared = False
    elif action == 'stop':
        state.is_active = False
        state.is_finished = True
    elif action == 'reset':
        state.is_active = False
        state.is_finished = False
        state.winner_declared = False
        # Reset votes
        candidates = Candidate.query.all()
        for c in candidates:
            c.votes = 0
        users = User.query.all()
        for u in users:
            u.has_voted = False
            
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/declare_winner', methods=['POST'])
def declare_winner():
    state = ElectionState.query.first()
    state.winner_declared = True
    state.is_active = False
    state.is_finished = True
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/results')
def results_page():
    state = ElectionState.query.first()
    # Results are visible if winner is declared or if admin is viewing (admin view handles separately)
    # But user requirement says: "Show Final Result Page... After election ends"
    
    # If election is not finished and winner not declared, simple users shouldn't see results?
    # User said "View live results" for Admin.
    # User said "Result display (winner)" for Everyone after election? 
    
    if not state.winner_declared and 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user.role != 'admin':
             flash("Results are not yet declared.")
             return redirect(url_for('vote_page'))

    candidates = Candidate.query.order_by(Candidate.votes.desc(), Candidate.name).all()
    total_votes = sum(c.votes for c in candidates)
    
    president = candidates[0] if len(candidates) > 0 else None
    vice_president = candidates[1] if len(candidates) > 1 else None
    
    return render_template('results.html', candidates=candidates, total_votes=total_votes, president=president, vice_president=vice_president, state=state)

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
