from flask import Flask, request, jsonify, send_from_directory, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from transformers import VisionEncoderDecoderModel, TrOCRProcessor
from transformers import BertTokenizer, BertForSequenceClassification
from PIL import Image
import io
import jwt
import datetime
from functools import wraps
import os

app = Flask(__name__)
CORS(app)


app.config['SECRET_KEY'] = 'Thisisasecretkey'  
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            token = token.split(' ')[1]  # Remove 'Bearer ' prefix
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['user_id']).first()
        except Exception as e:
            return jsonify({'message': 'Token is invalid', 'error': str(e)}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/')
def serve_index():
    return render_template('home.html')

@app.route('/<path:path>')
def serve_file(path):
    if path.endswith('.html'):
        return render_template(path)
    return send_from_directory('static', path)

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()

    if not all(k in data for k in ('name', 'email', 'password')):
        return jsonify({'message': 'Missing required fields'}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email already registered'}), 400

    hashed_password = generate_password_hash(data['password'], method='sha256')
    
    new_user = User(
        name=data['name'],
        email=data['email'],
        password=hashed_password
    )

    try:
        db.session.add(new_user)
        db.session.commit()
        
        token = jwt.encode({
            'user_id': new_user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
        }, app.config['SECRET_KEY'])

        return jsonify({
            'message': 'Registration successful',
            'token': token,
            'user': {
                'id': new_user.id,
                'name': new_user.name,
                'email': new_user.email
            }
        }), 201

    except Exception as e:
        return jsonify({'message': 'Error creating user', 'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()

    if not all(k in data for k in ('email', 'password')):
        return jsonify({'message': 'Missing required fields'}), 400

    user = User.query.filter_by(email=data['email']).first()

    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'message': 'Invalid credentials'}), 401

    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
    }, app.config['SECRET_KEY'])

    return jsonify({
        'message': 'Login successful',
        'token': token,
        'user': {
            'id': user.id,
            'name': user.name,
            'email': user.email
        }
    }), 200

@app.route('/api/user', methods=['GET'])
@token_required
def get_user(current_user):
    return jsonify({
        'user': {
            'id': current_user.id,
            'name': current_user.name,
            'email': current_user.email
        }
    }), 200

@app.route('/api/logout', methods=['POST'])
@token_required
def logout(current_user):

    return jsonify({'message': 'Logout successful'}), 200


@app.route('/api/reset-password-request', methods=['POST'])
def reset_password_request():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    
    if user:
        reset_token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, app.config['SECRET_KEY'])
        
       
        return jsonify({
            'message': 'Password reset instructions sent',
            'reset_token': reset_token
        }), 200
    
    return jsonify({'message': 'Email not found'}), 404

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    try:
        token_data = jwt.decode(data['token'], app.config['SECRET_KEY'], algorithms=["HS256"])
        user = User.query.get(token_data['user_id'])
        
        if user:
            user.password = generate_password_hash(data['new_password'], method='sha256')
            db.session.commit()
            return jsonify({'message': 'Password reset successful'}), 200
        
    except Exception as e:
        return jsonify({'message': 'Invalid or expired reset token', 'error': str(e)}), 401

    return jsonify({'message': 'Password reset failed'}), 400


processor = TrOCRProcessor.from_pretrained("microsoft/trocr-base-handwritten")
model = VisionEncoderDecoderModel.from_pretrained("microsoft/trocr-base-handwritten")

tokenizer = BertTokenizer.from_pretrained("bert-base-uncased")
bert_model = BertForSequenceClassification.from_pretrained("bert-base-uncased", num_labels=1)

def extract_text(image_bytes):
    image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    pixel_values = processor(image, return_tensors="pt").pixel_values
    generated_ids = model.generate(pixel_values)
    extracted_text = processor.batch_decode(generated_ids, skip_special_tokens=True)[0]
    return extracted_text

def grade_answer(extracted_text, keywords, weights):
    tokens = tokenizer(extracted_text, return_tensors="pt", padding=True, truncation=True)
    
    score = 0
    for keyword, weight in zip(keywords, weights):
        if keyword.lower() in extracted_text.lower():
            score += weight
    
    return score

@app.route('/upload', methods=['GET'])
def upload_form():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    image_bytes = file.read()
    extracted_text = extract_text(image_bytes)
    
    keywords = request.form.getlist('keywords')  
    weights = list(map(float, request.form.getlist('weights')))  
    
    score = grade_answer(extracted_text, keywords, weights)
    
    return jsonify({'extracted_text': extracted_text, 'score': score})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)