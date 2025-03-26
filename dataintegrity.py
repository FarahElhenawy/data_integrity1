from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import pyotp
import qrcode
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

# Set up the database URI with MySQL credentials
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/data_integrity'  # Updated URI with MySQL username and password
app.config['SECRET_KEY'] = 'farah'  # Changed secret key to 'farah'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Create Users table
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    twofa_secret = db.Column(db.String(256), nullable=False)

# Create Products table
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)

# Create the tables inside an application context
with app.app_context():
    db.create_all()

# User Registration with 2FA Setup
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']

    # Hash password
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # Generate a secret for Google Authenticator
    totp = pyotp.TOTP(pyotp.random_base32())
    secret = totp.secret

    # Store user in the database
    new_user = User(username=username, password=hashed_password, twofa_secret=secret)
    db.session.add(new_user)
    db.session.commit()

    # Generate QR code for Google Authenticator
    uri = totp.provisioning_uri(username, issuer_name="FlaskApp")
    img = qrcode.make(uri)
    img.save(f"{username}_qrcode.png")

    return jsonify({"message": "User registered successfully", "qr_code": f"{username}_qrcode.png"}), 201

# Verify Google Authenticator 2FA Code and return JWT Token
@app.route('/verify_2fa', methods=['POST'])
def verify_2fa():
    data = request.get_json()
    username = data['username']
    token = data['token']

    user = User.query.filter_by(username=username).first()
    if user:
        totp = pyotp.TOTP(user.twofa_secret)
        if totp.verify(token):
            # 2FA verified successfully, now generate JWT token with extended expiration (1 hour)
            expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Set expiration to 1 hour
            encoded_jwt = jwt.encode({'username': username, 'exp': expiration}, app.config['SECRET_KEY'], algorithm='HS256')
            return jsonify({
                "message": "2FA verification successful",
                "jwt_token": encoded_jwt
            }), 200
        else:
            return jsonify({"message": "Invalid 2FA token"}), 401
    return jsonify({"message": "User not found"}), 404

# User Login and JWT Token Generation
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']
    token = data['token']

    user = User.query.filter_by(username=username).first()
    if user and bcrypt.check_password_hash(user.password, password):
        totp = pyotp.TOTP(user.twofa_secret)
        if totp.verify(token):
            # Create JWT token with extended expiration (1 hour)
            expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Set expiration to 1 hour
            encoded_jwt = jwt.encode({'username': username, 'exp': expiration}, app.config['SECRET_KEY'], algorithm='HS256')
            return jsonify({"message": "Login successful", "jwt_token": encoded_jwt}), 200
        else:
            return jsonify({"message": "Invalid 2FA token"}), 401
    return jsonify({"message": "Invalid username or password"}), 401

# JWT Token Required for CRUD Operations
def token_required(f):
    @wraps(f)
    def wrapper_for_token(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"message": "Token is missing!"}), 403
        try:
            # Extract the token (remove 'Bearer ' prefix)
            token = token.split(" ")[1]
            
            # Decode the token
            decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(username=decoded_token['username']).first()
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired!"}), 403
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token!"}), 403
        return f(current_user, *args, **kwargs)
    return wrapper_for_token

# CRUD Operations for Products
@app.route('/products', methods=['POST'])
@token_required
def add_product(current_user):
    data = request.get_json()
    name = data['name']
    description = data['description']
    price = data['price']
    quantity = data['quantity']

    new_product = Product(name=name, description=description, price=price, quantity=quantity)
    db.session.add(new_product)
    db.session.commit()

    return jsonify({"message": "Product created successfully"}), 201

@app.route('/products', methods=['GET'])
@token_required
def get_products(current_user):
    products = Product.query.all()
    products_list = [{"id": product.id, "name": product.name, "description": product.description,
                      "price": product.price, "quantity": product.quantity} for product in products]
    return jsonify({"products": products_list})

@app.route('/products/<int:id>', methods=['PUT'])
@token_required
def update_product(current_user, id):
    data = request.get_json()
    product = Product.query.get(id)
    if product:
        product.name = data.get('name', product.name)
        product.description = data.get('description', product.description)
        product.price = data.get('price', product.price)
        product.quantity = data.get('quantity', product.quantity)
        db.session.commit()
        return jsonify({"message": "Product updated successfully"}), 200
    return jsonify({"message": "Product not found"}), 404

@app.route('/products/<int:id>', methods=['DELETE'])
@token_required
def delete_product(current_user, id):
    product = Product.query.get(id)
    if product:
        db.session.delete(product)
        db.session.commit()
        return jsonify({"message": "Product deleted successfully"}), 200
    return jsonify({"message": "Product not found"}), 404

if __name__ == "__main__":
    app.run(debug=True)
