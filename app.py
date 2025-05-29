from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
import datetime
import os

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_very_secure_random_string_that_you_must_change_in_production_environment')


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db = SQLAlchemy(app) 
bcrypt = Bcrypt(app) 

# --- Flask-Login Setup ---
login_manager = LoginManager(app)
login_manager.login_view = 'login' 
login_manager.login_message_category = 'info' 

@login_manager.user_loader
def load_user(user_id):
    """
    This function is required by Flask-Login. It loads a user from the database
    given their ID. Flask-Login uses this to manage user sessions across requests.
    """
    return User.query.get(int(user_id))

# --- Database Models ---

class User(db.Model, UserMixin): 
    """
    Database model for users.
    - id: Primary key for the user.
    - username: Unique username for login.
    - password: Stores the hashed password for security.
    - role: Defines the user's role ('user' for normal, 'admin' for authorized).
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), default='user', nullable=False) 

    def __repr__(self):
        """String representation of a User object."""
        return f"User('{self.username}', '{self.role}')"

    def is_admin(self):
        """Helper method to easily check if a user has the 'admin' role."""
        return self.role == 'admin'

class Incident(db.Model):
    """
    Database model for incidents reported.
    - id: Primary key for the incident.
    - title: Short title of the incident.
    - location: Location where the incident occurred.
    - description: Detailed description of the incident.
    - timestamp: Date and time when the incident was reported.
    - reported_by: Username of the reporter (defaults to 'Anonymous').
    - status: Current status of the incident (e.g., 'Active', 'Resolved').
    """
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now)
    reported_by = db.Column(db.String(100), default='Anonymous')
    status = db.Column(db.String(50), default='Active') 

    def __repr__(self):
        """String representation of an Incident object."""
        return f"Incident('{self.title}', '{self.location}', '{self.timestamp}')"


with app.app_context():
    db.create_all() 
    print("Database tables checked/created.")

  
    if User.query.filter_by(username='admin').first() is None:
        print("Creating default admin user...")
        # Hash the password securely before storing it in the database.
        hashed_password = bcrypt.generate_password_hash('admin_password').decode('utf-8')
        admin_user = User(username='admin', password=hashed_password, role='admin')
        db.session.add(admin_user)
        db.session.commit()
        print("Default admin user 'admin' created with password 'admin_password'.")

   
    if Incident.query.count() == 0:
        print("Adding initial dummy incidents...")
        incidents_data = [
            {"title": "Road Accident", "location": "Near Palasia Police Station", "description": "Minor collision, traffic slowing down.", "reported_by": "Traffic Police", "status": "Active"},
            {"title": "Water Logging", "location": "Indore Railway Station Underpass", "description": "Heavy rain caused temporary water logging.", "reported_by": "Local Resident", "status": "Resolved"},
            {"title": "Electricity Outage", "location": "Vijay Nagar, Sector B", "description": "Power cut reported in Block B, restoration expected by 6 PM.", "reported_by": "M.P.E.B", "status": "Active"},
        ]
        for data in incidents_data:
            incident = Incident(**data)
            db.session.add(incident) 
        db.session.commit() 
        print("Dummy incidents added.")

# --- Request Hooks ---
@app.before_request
def common_request_setup():
    """
    This function runs before every single request.
    Useful for common tasks like logging, setting up context, etc.
    """
    pass

# --- Routes ---

@app.route('/')
def index():
    """
    Displays the homepage with a list of all incidents.
    Incidents are ordered by timestamp in descending order (newest first).
    """
    incidents = Incident.query.order_by(Incident.timestamp.desc()).all()
    current_year = datetime.datetime.now().year
    return render_template('index.html', incidents=incidents, current_year=current_year, current_user=current_user)

@app.route('/incident/<int:incident_id>')
def incident_detail(incident_id):
    """
    Displays the detailed information for a specific incident.
    Uses get_or_404 to automatically return a 404 error if the incident ID is not found.
    """
    incident = Incident.query.get_or_404(incident_id)
    current_year = datetime.datetime.now().year
    return render_template('incident_detail.html', incident=incident, current_year=current_year, current_user=current_user)

@app.route('/report', methods=['GET', 'POST'])
@login_required 
def report_incident():
    """
    Handles the reporting of new incidents.
    - On GET request: Displays the incident reporting form.
    - On POST request: Processes the form submission, validates data, and saves the new incident to the database.
    """
    current_year = datetime.datetime.now().year

    if request.method == 'POST':
        title = request.form.get('title')
        location = request.form.get('location')
        description = request.form.get('description')
        reported_by = current_user.username if current_user.is_authenticated else 'Anonymous'

        if not title or not location or not description:
            flash('All required fields (Title, Location, Description) must be filled out!', 'error')
            return render_template('report_incident.html', current_year=current_year,
                                   title=title, location=location, description=description, reported_by=reported_by)

        new_incident = Incident(
            title=title,
            location=location,
            description=description,
            reported_by=reported_by
        )

        try:
            db.session.add(new_incident) 
            db.session.commit() 
            flash('Incident reported successfully!', 'success')
            return redirect(url_for('index')) 
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while reporting the incident: {e}', 'error')
            return render_template('report_incident.html', current_year=current_year,
                                   title=title, location=location, description=description, reported_by=reported_by)

    return render_template('report_incident.html', current_year=current_year,
                           reported_by=current_user.username if current_user.is_authenticated else '')


@app.route('/incident/<int:incident_id>/resolve', methods=['POST'])
@login_required
def resolve_incident(incident_id):
    """
    Allows an authorized user (specifically, an 'admin') to mark an incident as resolved.
    This route only accepts POST requests for data modification.
    """
    if not current_user.is_admin():
        flash('You are not authorized to mark incidents as resolved. Only administrators can perform this action.', 'error')
        return redirect(url_for('incident_detail', incident_id=incident_id))

    incident = Incident.query.get_or_404(incident_id)

    if incident.status == 'Resolved':
        flash('Incident is already marked as Resolved.', 'info')
    else:
        incident.status = 'Resolved' 
        try:
            db.session.commit() 
            flash(f'Incident "{incident.title}" has been marked as Resolved!', 'success')
        except Exception as e:
            db.session.rollback() 
            flash(f'An error occurred while resolving the incident: {e}', 'error')

    return redirect(url_for('incident_detail', incident_id=incident.id))

# --- Authentication Routes ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Handles user registration.
    - On GET request: Displays the registration form.
    - On POST request: Processes the form, validates input, hashes password, and creates a new user.
    New users are assigned the 'user' role by default.
    """
    if current_user.is_authenticated:
        flash('You are already logged in.', 'info')
        return redirect(url_for('index'))

    current_year = datetime.datetime.now().year
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Basic server-side validation for required fields and password match.
        if not username or not password or not confirm_password:
            flash('All fields are required!', 'error')
            return render_template('register.html', current_year=current_year, username=username)

        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return render_template('register.html', current_year=current_year, username=username)

        if User.query.filter_by(username=username).first():
            flash('That username is already taken. Please choose a different one.', 'error')
            return render_template('register.html', current_year=current_year, username=username)

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password, role='user')

        try:
            db.session.add(new_user) 
            db.session.commit() 
            flash('Your account has been created! You can now log in.', 'success')
            return redirect(url_for('login')) 
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred during registration: {e}', 'error')
            return render_template('register.html', current_year=current_year, username=username)

    # For a GET request, display the empty registration form.
    return render_template('register.html', current_year=current_year)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handles user login.
    - On GET request: Displays the login form.
    - On POST request: Processes credentials, authenticates user, and logs them in using Flask-Login.
    """
    if current_user.is_authenticated: # If user is already logged in, redirect them away from the login page.
        flash('You are already logged in.', 'info')
        return redirect(url_for('index'))

    current_year = datetime.datetime.now().year
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        # Check if the user exists and if the provided password matches the stored hashed password.
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user) # Log the user in using Flask-Login.
            flash(f'Welcome, {user.username}! You are logged in as {user.role}.', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'error')

    # For a GET request, display the empty login form.
    return render_template('login.html', current_year=current_year)

@app.route('/logout')
@login_required 
def logout():
    """Logs the current user out."""
    logout_user() 
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# --- Error Handlers ---
@app.errorhandler(404)
def page_not_found(error):
    """
    Custom 404 error page.
    This function is called when a requested URL is not found.
    """
    current_year = datetime.datetime.now().year
    return render_template('404.html', current_year=current_year, current_user=current_user), 404

# --- Application Entry Point ---
if __name__ == '__main__':
    app.run(debug=True)
