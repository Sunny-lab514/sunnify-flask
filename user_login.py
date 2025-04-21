from flask import Flask, request, redirect, jsonify, session, url_for, render_template, flash
from flask_cors import CORS
import mysql.connector
import os
from flask_bcrypt import Bcrypt
import razorpay
from flask_jwt_extended import JWTManager, create_access_token
import jwt
import datetime
import smtplib
from flask_mail import Mail, Message

app = Flask(__name__)
app.secret_key = "your_secret_key"
CORS(app)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'vermasunny502@gmail.com'  # tumhara email
app.config['MAIL_PASSWORD'] = 'qubi woqh wftr nbcu'      # Gmail ka App Password
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)


# 🔹 Database Connection Function
def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        port=os.getenv("DB_PORT") 
    )

bcrypt = Bcrypt(app)

# 🔹 Home Route
@app.route('/')
def home():
    return "Sunnify is Live!"

# 🔹 User Registration API
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')

    db = get_db_connection()
    cursor = db.cursor()
    try:  # Try block properly indented
        cursor.execute("INSERT INTO users (email, password) VALUES (%s, %s)", (data['email'], hashed_password))
        db.commit()
        return jsonify({"message": "User registered successfully"}), 201
    except mysql.connector.IntegrityError:
        return jsonify({"message": "Email already exists"}), 400
    finally:
        cursor.close()
        db.close()


    return jsonify({"message": "User registered successfully"}), 201

# 🔹 Middleware for Token Verification
def verify_token():
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return None
    try:
        token = auth_header.split(" ")[1]
        decoded_token = jwt.decode(token, app.secret_key, algorithms=["HS256"])
        return decoded_token["user_id"]
    except Exception:
        return None

# 🔹 Buy Now API
@app.route('/buy', methods=['POST'])
def buy():
    user_id = verify_token()
    if not user_id:
        return jsonify({"message": "Enter login first"}), 403

    data = request.json
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("INSERT INTO orders (user_id, product_id) VALUES (%s, %s)", (user_id, data['product_id']))
    db.commit()
    cursor.close()
    db.close()
    
    return jsonify({"message": "Order Placed Successfully"}), 200

# 🔹 Razorpay API Keys
RAZORPAY_KEY_ID = "rzp_test_yBpkE6BX1ec9ll"
RAZORPAY_KEY_SECRET = "xYXcwKpO1LzKQ7vLTaMq8dNL"
razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

# 🔹 Order Create API
@app.route('/create_order', methods=['POST'])
def create_order():
    data = request.json
    amount = data['amount'] * 100  # ₹1 = 100 Paise
    
    order_data = {
        "amount": amount,
        "currency": "INR",
        "payment_capture": "1"
    }

    order = razorpay_client.order.create(order_data)
    return jsonify(order)

# 🔹 Payment Verification API
@app.route('/verify_payment', methods=['POST'])
def verify_payment():
    data = request.json

    try:
        params_dict = {
            'razorpay_order_id': data['razorpay_order_id'],
            'razorpay_payment_id': data['razorpay_payment_id'],
            'razorpay_signature': data['razorpay_signature']
        }

        result = razorpay_client.utility.verify_payment_signature(params_dict)
        if result:
            return jsonify({"message": "Payment Successful"}), 200
        else:
            return jsonify({"message": "Payment Verification Failed"}), 400

    except Exception as e:
        return jsonify({"message": "Error", "error": str(e)}), 500

CORS(app)  # Cross-Origin requests allow karega
bcrypt = Bcrypt(app)
# Secret key for JWT authentication
app.config["JWT_SECRET_KEY"] = "your_secret_key"
jwt = JWTManager(app)

# Connect to MySQL Database
db = mysql.connector.connect(
    host=os.getenv("DB_HOST"),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
    database=os.getenv("DB_NAME"),
    port=os.getenv("DB_PORT")  
)
cursor = db.cursor()
# **Signup API**
@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json()
    name = data.get("name", "").strip()
    email = data.get("email", "").strip()
    password_raw = data.get("password", "")

    if not name or not email or not password_raw:
        return jsonify({"message": "Name, Email and Password are required"}), 400

    password = bcrypt.generate_password_hash(password_raw).decode("utf-8")

    try:
        cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", (name, email, password))
        db.commit()
        return jsonify({"message": "User Registered"}), 201
    except mysql.connector.IntegrityError:
        return jsonify({"message": "Email already exists"}), 400
# **Login API**
@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data["email"]
    password = data["password"]

    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("SELECT id, email, password, name FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    cursor.close()
    db.close()

    if not user:
        return jsonify({"message": "User Not Found"}), 400

    user_id, user_email, hashed_password, user_name = user

    if not bcrypt.check_password_hash(hashed_password, password):
        return jsonify({"message": "Invalid Credentials"}), 400

    #Add token (optional - can be real JWT later)
    return jsonify({
        "message": "Login successful",
        "token": "dummy-token",  # add a token for frontend use
        "name": user_name,
        "email": user_email,
        "user_id": user_id
    }), 200
# Function to send email notification
def send_notification(email):
    sender_email = "vermasunny502@gmail.com"  # Replace with your email
    sender_password = "qubi woqh wftr nbcu"  # Replace with your email password
    receiver_email = "vermasunny502@gmail.com"  # Replace with your phone email for SMS notification

    subject = "New Subscriber on Sunnify"
    body = f"New user subscribed with email: {email}"

    message = f"Subject: {subject}\n\n{body}"

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver_email, message)
        server.quit()
        print("Notification sent!")
    except Exception as e:
        print(f"Error sending email: {e}")

# API Route to Handle Subscription
@app.route('/subscribe', methods=['POST'])
def subscribe():
    data = request.json
    email = data.get("email")
    print(f"Received subscription request for: {email}")

    if not email:
        return jsonify({"message": "Invalid email"}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT email FROM subscribers WHERE email = %s", (email,))
        existing_email = cursor.fetchone()

        if existing_email:
            print("Already subscribed.")
            # Stop here if already subscribed
            return jsonify({"message": "You are already subscribed!"}), 400

        # Insert new email
        cursor.execute("INSERT INTO subscribers (email) VALUES (%s)", (email,))
        conn.commit()
        print("Email inserted in DB successfully")

        cursor.close()
        conn.close()

        #  Now send notification *after* DB insert only
        send_notification(email)
        print("Notification sent successfully")

        # Finally, return success
        return jsonify({"message": "You are successfully subscribed!"}), 200

    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return jsonify({"message": "Database error"}), 500
# Function to send email notification
def send_feedback_notification(fullname, email, message):
    sender_email = "vermasunny502@gmail.com"  # Change this
    sender_password = "qubi woqh wftr nbcu"  # Change this
    receiver_email = "vermasunny502@gmail.com"  # Your email for notifications

    subject = f"Feedback from {fullname}"
    body = f"User {fullname} ({email}) submitted feedback:\n\n{message}"

    message = f"Subject: {subject}\n\n{body}"

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver_email, message)
        server.quit()
        print("Feedback notification sent!")
    except Exception as e:
        print(f"Error sending email: {e}")

# API Route to Handle Feedback Submission
@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    data = request.json
    fullname = data.get("fullname")
    email = data.get("email")
    message = data.get("message")

    if not fullname or not email or not message:
        return jsonify({"message": "Invalid data"}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("INSERT INTO feedback (fullname, email, message) VALUES (%s, %s, %s)",
                       (fullname, email, message))
        conn.commit()
        cursor.close()
        conn.close()

        send_feedback_notification(fullname, email, message)

        return jsonify({"message": "Thank you for your feedback!"}), 200

    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return jsonify({"message": "Database error"}), 500

    # Check if user exists
    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()

    if not user:
        # New user - insert
        cursor.execute("INSERT INTO users (email, name, picture) VALUES (%s, %s, %s)", (email, name, picture))
        db.commit()
        return jsonify({"message": "New user created", "name": name})

    return jsonify({"message": "User already exists", "name": user[2]})
#Confirm order API
@app.route('/confirm_order', methods=['POST'])
def confirm_order():
    try:
        data = request.get_json()
        print("\n🔻 Received JSON:", data)

        user_id = data.get('user_id')
        user_name = data.get('user_name')
        user_email = data.get('user_email')
        product_id = data.get('product_id')
        print(" Product ID:", product_id)

        street = data.get('street', '').lower()
        city = data.get('city', '').lower()
        state = data.get('state')
        pincode = data.get('pincode')
        print(f"📍 Address: {street}, {city}, {state}, {pincode}")

        if pincode != "208017" or "kalyanpur" not in (street + city):
            return jsonify({"status": "out_of_range", "message": "Delivery is not available in your area."}), 200

        db = get_db_connection()
        cursor = db.cursor()

        cursor.execute("SELECT name, price, quantity FROM products WHERE id = %s", (product_id,))
        product = cursor.fetchone()
        if not product:
            print(" Product not found!")
            cursor.close()
            db.close()
            return jsonify({"status": "fail", "message": "Invalid product ID"}), 404

        product_name, price, quantity = product
        Number_of_items = 1

        print(" Inserting order...")
        cursor.execute("""
            INSERT INTO orders (product_id, product_name, Number_of_items, user_id, user_name, user_email, address, quantity)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (product_id, product_name, Number_of_items, user_id, user_name, user_email, f"{street}, {city}, {state} - {pincode}", quantity))

        db.commit()
        cursor.close()
        db.close()

        print(" Sending order email...")
        send_order_email(product_name, price, Number_of_items, user_name, f"{street}, {city}, {state} - {pincode}", user_email, quantity)

        return jsonify({"status": "success", "message": "Order placed successfully!"}), 200

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"status": "fail", "message": str(e)}), 500

def send_order_email(product_name, price, Number_of_items, username, address, user_email, quantity):
    msg = Message(
        subject=f"New Order from {username}",
        sender="vermasunny502@gmail.com",
        recipients=["vermasunny502@gmail.com", user_email],  # Send to user as well
        body=f"Order Details:\nProduct: {product_name}\nNumber_of_items: {Number_of_items}\nPrice: {price}\nAddress: {address}\nQuantity: {quantity}"
    )
    try:
        mail.send(msg)
        print("Email sent successfully!")  # Log success
    except Exception as e:
        print(f"Email sending failed: {e}")  # Log failure

#order placed sucessfully API
@app.route('/order_success')
def order_success():
    return "<h2>Order Placed Successfully!</h2><a href='/products'>Back to Products</a>"

#buy now API
@app.route('/buy_now/<int:product_id>', methods=['GET'])
def buy_now(product_id):
    session['selected_product_id'] = product_id
    session['selected_quantity'] = request.args.get('qty')  # if from cart.html
    return render_template('address_modal.html')

#Products API
@app.route('/products')
def products():
    return render_template("vegetable_newpage.html")
#get_user_by_token 
@app.route("/api/get_user_by_token", methods=["POST"])
def get_user_by_token():
    data = request.get_json()
    token = data.get("token")
    email = data.get("email")

    if not token:
        return jsonify({"status": "fail", "message": "Token is missing"}), 400
    if not email:
        return jsonify({"status": "fail", "message": "Email is missing"}), 400

    db = get_db_connection()
    cursor = db.cursor()

    cursor.execute("SELECT id, email FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()

    cursor.close()
    db.close()

    if not user:
        return jsonify({"status": "fail", "message": "User not found"}), 404

    user_id, email = user
    return jsonify({
        "status": "success",
        "user_id": user_id,
        "email": email
    }), 200
#cart_shopping API
@app.route('/cart_checkout', methods=['POST'])
def cart_checkout():
    try:
        data = request.get_json()
        print("Received data:", data)

        address_data = data.get('address', {})
        user_id = address_data.get('user_id')
        user_name = address_data.get('user_name')
        user_email = address_data.get('user_email')
        street = address_data.get('street', '').lower()
        city = address_data.get('city', '').lower()
        state = address_data.get('state')
        pincode = address_data.get('pincode')
        address = f"{street}, {city}, {state} - {pincode}"

        print(f"User ID: {user_id}, Address: {address}")

        if pincode != "208017" or "kalyanpur" not in (street + city):
            return jsonify({"status": "out_of_range", "message": "Delivery not available."}), 200

        cart_items = data.get('cartItems', [])
        db = get_db_connection()
        cursor = db.cursor()

        email_products = []  # For email summary

        for item in cart_items:
            product_id = item.get('product_id')
            quantity = item.get('quantity', 1)

            cursor.execute("SELECT name, price, quantity FROM products WHERE id = %s", (product_id,))
            product_data = cursor.fetchone()
            if not product_data:
                cursor.close()
                db.close()
                return jsonify({"status": "fail", "message": "Invalid product ID"}), 404

            product_name, price, available_quantity = product_data

            # Insert into orders
            cursor.execute("""
                INSERT INTO orders (product_id, product_name, Number_of_items, user_id, user_name, user_email, address, quantity)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (product_id, product_name, quantity, user_id, user_name, user_email, address, available_quantity))

            # Prepare for email
            email_products.append({
                'product_name': product_name,
                'quantity': quantity,
                'price': price,
                'number_of_items': quantity
            })

        db.commit()
        cursor.close()
        db.close()

        # Send the email
        send_bulk_order_email(email_products, user_name, address, user_email)

        return jsonify({"status": "success", "message": "Order placed successfully!"}), 200

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"status": "fail", "message": str(e)}), 500
def send_bulk_order_email(products, username, address, user_email):
    body_lines = [f"Order Summary for {username}:\n"]
    for p in products:
        body_lines.append(
            f"Product: {p['product_name']} | Qty: {p['quantity']} | Price: Rs.{p['price']} x {p['number_of_items']}"
        )

    body_lines.append(f"\nDelivery Address: {address}")

    msg = Message(
        subject=f"New Order from {username}",
        sender="vermasunny502@gmail.com",
        recipients=["vermasunny502@gmail.com", user_email],
        body="\n".join(body_lines)
    )

    try:
        mail.send(msg)
        print("Bulk order email sent successfully!")
    except Exception as e:
        print(f"Email sending failed: {e}")

# **Run the Server**
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)

