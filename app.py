from flask import Flask, render_template, request, jsonify, flash
from werkzeug.utils import secure_filename
import os
from flask import redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy 
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
from flask.cli import with_appcontext
import click
from functools import wraps
from flask_migrate import Migrate
from math import radians, cos, sin, sqrt, atan2
from flask_socketio import SocketIO, emit
import pdfkit

global_config = {
    'X' : 'results/vis/'
}
def calculate_distance(lat1, lon1, lat2, lon2):
    # Radius of the Earth in kilometers
    R = 6371.0

    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    dlon = lon2 - lon1
    dlat = lat2 - lat1

    a = sin(dlat / 2)**2 + cos(lat1) * cos(lat2) * sin(dlon / 2)**2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))

    distance = R * c
    return distance


from modeltest import process_image
from modelsalienttest import process_salient_image
from fpdf import FPDF

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['RESULTS_FOLDER'] = os.path.join('static', 'results')
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 MB limit per file
app.config['SECRET_KEY'] = 'chirayus_dl_project'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")


# =============================== Database creation ===================================
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(100))

@app.cli.command("create-admin")
@click.argument("email")
@click.argument("password")
@click.argument("name")
@click.argument("city")
@with_appcontext
def create_admin(email, password, name, city):
    hashed_password = generate_password_hash(password)
    new_admin = Admin(email=email, password_hash=hashed_password, name=name, city=city)
    db.session.add(new_admin)
    db.session.commit()
    print(f'Admin {email} created successfully.')

# database for user information
class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(120), unique = True, nullable = False)
    name = db.Column(db.String(120), nullable = False)
    password_hash = db.Column(db.String(120), nullable = False)
    requests = db.relationship('Request', backref = 'author', lazy = True)

# datasbase containing inforation regarding user requests
class Request(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable = False)
    type = db.Column(db.String(100), nullable = False)
    result_image_path = db.Column(db.String(300))
    cost_estimation = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default = db.func.current_timestamp())
    agent_id = db.Column(db.Integer, db.ForeignKey('agent.id'))
    status = db.Column(db.String(20), default='pending')
    distance = db.Column(db.Float, nullable= True, default = True)
    username = db.Column(db.String(100), nullable=True, default='Sarrthi_User') 
    user_contact = db.Column(db.String(100), nullable = True, default ='saarthi_user@gmail.com') 
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

# database containing agent information
class Agent(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash=db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    city = db.Column(db.String(120), nullable=False)
    shop = db.Column(db.String(120), nullable=False)
    latitude = db.Column(db.Float, nullable=True)  # Add latitude
    longitude = db.Column(db.Float, nullable=True)  # Add longitude
    phone = db.Column(db.Integer, nullable=False)
    is_available = db.Column(db.Boolean, default=True)
    requests = db.relationship('Request', backref='agent', lazy=True)
    
    def __repr__(self):
        return f"<Agent {self.email}>" 
    
with app.app_context():
    db.create_all()

migrate = Migrate(app, db)
#================================= Database Creation Ends Here ========================================

#================================ User Authentication Routes =========================================
@app.route('/register', methods = ['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        user = User(email = email, name = name, password_hash = hashed_password)
        db.session.add(user)
        db.session.commit()
        #return jsonify({'message' : 'Registered Successfully'})
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods = ['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            return redirect(url_for('user_dashboard'))
        return 'invalid credentials'
    return render_template('login.html')

@app.route('/logout')
def logout():    
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/user_dashboard')
def user_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if user:
        return render_template('user_dashboard.html', user=user, requests=user.requests, user_id=session['user_id'])
    return 'User not found'

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('You need to be logged in to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

#===================================== User Authentication Routes Ends Here =================================

#===================================== Admin Authentication Routes ==========================================

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        admin = Admin.query.filter_by(email=email).first()
        if admin and check_password_hash(admin.password_hash, password):
            session['admin_id'] = admin.id
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid credentials')
    return render_template('admin_login.html')

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))
    admin = Admin.query.get(session['admin_id'])
    if admin:
        return render_template('admin_dashboard.html', admin=admin)
    else:
        return "Admin not found", 404


@app.route('/admin/add_agent', methods=['GET', 'POST'])
@admin_required
def add_agent():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        name = request.form['name']
        city = request.form['city']
        shop = request.form['shop']
        phone = request.form['phone']
        latitude = request.form['latitude']
        longitude = request.form['longitude']
        hashed_password = generate_password_hash(password)
        new_agent = Agent(email=email, password_hash=hashed_password, name=name, city=city, shop=shop, phone=phone, latitude=latitude, longitude=longitude)
        db.session.add(new_agent)
        db.session.commit()
        flash('Agent created successfully.', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('add_agent.html')

#============================== Admin Authentication Routes Ends Here ==============================================

#============================== Agent Authentication Routes ========================================================

@app.route('/agent_login', methods=['GET', 'POST'])
def agent_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        agent = Agent.query.filter_by(email=email).first()
        if agent and check_password_hash(agent.password_hash, password):
            session['agent_id'] = agent.id
            return redirect(url_for('agent_dashboard'))
        else:
            return 'invalid credentials', 401
    return render_template('agent_login.html')

@app.route('/agent_logout')
def agent_logout():
    session.pop('agent_id', None)
    return redirect(url_for('agent_login'))

@app.route('/agent_dashboard')
def agent_dashboard():
    if 'agent_id' not in session:
        return redirect(url_for('agent_login'))
    agent = Agent.query.get(session['agent_id'])
    if not agent:
        return 'Agent not found', 404

        # Get status from query parameter, default to 'pending'
    status = request.args.get('status', 'pending')

        # Filter requests by the status
    # filtered_requests = [req for req in agent.requests if req.status == status]
    # return render_template('agent_dashboard.html', agent=agent, requests=filtered_requests)
    filtered_requests = Request.query.filter_by(agent_id=agent.id, status=status) \
                                     .order_by(Request.created_at.desc()).all()
    return render_template('agent_dashboard.html', agent=agent, requests=filtered_requests)


#========================================= Agent Authentication Routes Ends Here =======================================

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['RESULTS_FOLDER'], exist_ok=True)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/object_detection', methods=['GET', 'POST'])
@login_required
def object_detection():
    if request.method == 'POST':
        files = request.files.getlist('images')
        if not files:
            return jsonify({'error': 'No files provided'}), 400
        results = []
        all_repair_costs = []
        for file in files:
            if file and allowed_file(file.filename):
                global global_config
                global_config['X']= 'results/vis/' 
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                print("Saved original file to:", filepath) 
                # Process the image through your ML model here
                repair_cost_prediction = process_image(filepath, app.config['RESULTS_FOLDER'])
                print("I am repair cost prediction",repair_cost_prediction)

                # split_point = repair_cost_prediction.index('&') + 1  # find the first '$' and adjust the position just after it
                # repair_cost = repair_cost_prediction[:split_point-1]  # everything before the first '$'
                # print("I am split", split_point)
                # predict = repair_cost_prediction[split_point:] 
                parts = repair_cost_prediction.split('&')

                # Assign each part to a separate variable
                repair_cost = parts[0]  # The first part which contains the repair costs
                labels = parts[1]  # The second part which contains labels
                scores = parts[2]  # The third part which contains scores
                bboxes = parts[3]  # The fourth part which contains bounding boxes
                total_cost_report = parts[4]
                print("I am repair cost",repair_cost)
                print("I am predict",labels)
                print("I am scores", scores)
                print("I am bboxes",bboxes)
                
                if repair_cost.startswith('[') and repair_cost.endswith(']'):
                    repair_cost = repair_cost[1:-1] 
                repair_cost_list = repair_cost.split(", ")
                all_repair_costs.extend(repair_cost)
                global_config['X'] = global_config['X'] + filename
                processed_salient_od_filepath = process_salient_image(filepath, app.config['RESULTS_FOLDER'])
                results.append({
                    'original': 'uploads/' + filename,  # Use relative path for web access
                    'processed': 'results/vis/' + filename,  # Use relative path for web access static\results\vis\0000test.jpg
                    'boxesonly': 'results/cost/'+ filename,
                    'salient_od':'results/mask/' + filename,
                })
                #results.append({'original': filepath, 'processed': processed_file_path})
                print("The result is:",results, repair_cost)
            else:
                return jsonify({'error': 'Invalid file type'}), 400
        return render_template('results.html', results=results, repair_cost = repair_cost_list, labels = labels, scores= scores, bboxes = bboxes, total_cost_report=total_cost_report)
    return render_template('object_detection.html')

@app.route('/api/agent_accept_request', methods=['POST'])
def agent_accept_request():
    request_id = request.json['request_id']
    agent_id = request.json['agent_id']
    # Logic to accept request and potentially notify the user
    return jsonify({'message': 'Request accepted', 'request_id': request_id, 'agent_id': agent_id})

def notify_user_about_agent(request):
    agent = Agent.query.get(request.agent_id)
    user = User.query.get(request.user_id)
    # Example: Send notification/message to user's chatbot session
   # send_chatbot_message(user.id, f"Your request has been accepted by {agent.name} at {agent.shop}. Contact: {agent.phone}")
def emit_agent_info(message, user_id, action_type):
    """Function to emit messages to connected clients."""
    print(f"Emitting to user {user_id}: {message}")
    emit('agent_info', {'message': message, 'user_id': str(user_id), 'action_type': action_type}, namespace='/', broadcast=True)


@app.route('/agent/response/<int:request_id>/<action>', methods=['POST'])
def handle_agent_response(request_id, action):
    request = Request.query.get(request_id)
    if not request:
        return jsonify({'message' : 'Request not found'}), 404
    
    if action == 'accept':
        request.status = 'in_progress'
        db.session.commit()
        print(f"I am reueat {request}")
        # websockt emit to botui
        agent = Agent.query.get(request.agent_id)
        user = User.query.get(request.user_id)
        print(f"I am user and agent {user.id} - {agent.name}")
        message = f'''Your request has been accepted by {agent.name} at {agent.shop}. Contact: {agent.phone}. \n He is {request.distance} miles away from you. and 
        should be at your location in some time.'''
        print(message)
        emit_agent_info(message, user.id, action_type='default')

    elif action == 'complete':
        request.status = 'completed'
        db.session.commit()
        user = User.query.get(request.user_id)
        message = f"Your request {request.type} has been completed. Please proceeed to update your monthly report" #Please proceed to payment.
        emit_agent_info(message, user.id,  action_type="prompt_payment")  # Notify user that service is completed
        # Optionally, trigger BotUI for payment here
    
    elif action == 'cancel':
        request.status = 'cancelled'
        db.session.commit()
        user = User.query.get(request.user_id)
        message = "Your request has been cancelled. Please try again !!!!"
        emit_agent_info(message, user.id, action_type='default')  # Notify user about cancellation

    elif action == 'reject':
        request.status = 'rejected'
        db.session.commit()
        user = User.query.get(request.user_id)
        assign_request_to_next_nearest_agent(request)
        message = 'Request Rejected, Looking for another agent.'
        emit_agent_info(message, user.id, action_type='default')  # Notify user about rejection
        
    else:
        return jsonify({'error': 'Invalid Action'}), 400

    return jsonify({'message': f'Request {action}ed'})


def assign_request_to_next_nearest_agent(request):
    all_agents = Agent.query.order_by(Agent.is_available.desc()).all()  # Assuming all agents are sorted by availability or other criteria
    current_agent_index = next((index for index, agent in enumerate(all_agents) if agent.id == request.agent_id), None)
    
    # Start from the next agent in the list
    for next_agent in all_agents[current_agent_index + 1:]:
        if next_agent.is_available:
            request.agent_id = next_agent.id
            request.status = 'pending'
            db.session.commit()
            break                

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



# ========================================== ChatBot Routes Starts here ===========================================

@app.route('/api/location_help', methods = ['POST'])
@login_required
def location_help():
    help_type = request.form['helpType']
    latitude = float(request.form['latitute'])
    longitude = float(request.form['longitude'])
    address = request.form['address']
    estimated_cost, agent_phone = find_nearest_agent_and_cost(latitude, longitude, help_type)
    print(f"I am the address {address} and help_type {help_type}")
    # Optionally update agent's dashboard or notify them
    notify_agent_of_request(agent_phone, help_type, latitude, longitude)
    return jsonify({'estimated_cost': estimated_cost, 'agent_phone': agent_phone})

@app.route('/api/create_request', methods= ['POST'])
@login_required
def create_request():
    data = request.get_json()
    user_id = data.get('user_id')
    user = User.query.get(user_id)
    if not user_id:
        return jsonify({'error': 'user_id is missing'}), 400
    user_id = request.json['user_id']
    help_type = request.json['help_type']
    latitude = request.json['latitude']
    longitude = request.json['longitude']
    address = request.json['address']
    print(global_config['X'])
    nearest_agent, distance = find_nearest_agent(latitude, longitude)
    new_request = Request(
        user_id = user_id,
        agent_id=nearest_agent.id,
        type = help_type,
        result_image_path = global_config['X'],
        cost_estimation = 99,
        status = 'pending',
        distance = distance,
        username = user.name,
        user_contact = user.email 
    )
    db.session.add(new_request)
    db.session.commit()
    
    return jsonify({'message' : 'Request Created', 'request_id': new_request.id})

def calculate_distance(lat1, lon1, lat2, lon2):
    # Radius of the Earth in kilometers
    R = 6371.0

    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    dlon = lon2 - lon1
    dlat = lat2 - lat1

    a = sin(dlat / 2)**2 + cos(lat1) * cos(lat2) * sin(dlon / 2)**2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))

    distance = R * c
    return distance

def find_nearest_agent(lat, lng):
    min_distance = float('inf')
    nearest_agent = None
    agents = Agent.query.filter_by(is_available=True).all()
    for agent in agents:
        if agent.latitude and agent.longitude:
            distance = calculate_distance(lat, lng, agent.latitude, agent.longitude)
            if distance < min_distance:
                min_distance = distance
                nearest_agent = agent
    min_distance = round(min_distance, 2)
    return nearest_agent , min_distance

    
def find_nearest_agent_and_cost(lat, lng, help_type):
    # Placeholder function, replace with real database queries and logic
    return 100, '123-456-7890'  # Dummy cost and agent phone number



def notify_agent_of_request(agent_phone, help_type, lat, lng):
    # Implement logic to notify or update the agent's dashboard
    pass
    

@app.route('/generate_pdf')
def generate_pdf():
    try:
        # Render your template
        rendered = render_template('report.html')
        
        # Convert to PDF
        pdf = pdfkit.from_string(rendered, False)
        
        # Create response
        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'attachment; filename="report.pdf"'
        return response
    except Exception as e:
        return str(e)  # Return the error message

@app.route('/download_report')
def download_report():
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Damage Report", ln=True, align='C')
    # Add more data to your PDF here
    response = make_response(pdf.output(dest='S').encode('latin1'))
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=report.pdf'
    return response


if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
    #app.run(debug=True, host='0.0.0.0', port=5000)
