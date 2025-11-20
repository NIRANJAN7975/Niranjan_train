from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
import joblib
import pandas as pd
import os
import math
from pymongo import MongoClient
import logging
from datetime import timedelta
from werkzeug.utils import secure_filename
import cv2
import numpy as np
from tensorflow.keras.models import load_model  # type: ignore
import gc
import tensorflow as tf

from io import BytesIO
import base64


import smtplib
import random
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import pytz
from bson import ObjectId


# Initialize the app and setup CORS
app = Flask(__name__)
CORS(app, supports_credentials=True)

# Secret key for session management
app.secret_key = os.urandom(24)

# Set session to be permanent and set a longer session lifetime
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load models and data
cls = joblib.load('police_up.pkl')
en = joblib.load('label_encoder_up.pkl')
df1 = pd.read_csv('Sih_police_station_data.csv')
model = joblib.load('human_vs_animal.pkl')
df2 = pd.read_csv('districtwise-crime-against-women (1).csv')
df2 = df2[['registeration_circles', 'total_crime_against_women']]

# Define function to classify crime alert
def crime_indicator(crime_count):
    if crime_count < 50:
        return '🟢Green'
    elif 50 <= crime_count <= 500:
        return '🟡Yellow'
    else:
        return '🔴Red'

df2['indicator'] = df2['total_crime_against_women'].apply(crime_indicator)

# MongoDB connection
client = MongoClient("mongodb+srv://niranjanniranjann6:nYOhy31ljdHBYhj3@cluster0.dw1td.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client['new_train']
users_collection = db['users']
otp_collection = db['otp_storage']  
messages_collection = db['messages']
reviews = db['reviews']
App_reviews = db['App_reviews']
booked_seats_collection=db['ticket_records']
orders_collection = db['orders']




@app.route('/submit-order', methods=['POST'])
def submit_order():
    try:
        data = request.json
        username = data.get("username")
        mobile = data.get("mobile")
        order_items = data.get("orderItems", [])
        selected_seats = data.get("selectedSeats", [])
        grand_total = data.get("grandTotal")
        otp = data.get("otp")
        location = data.get("location", {})

        latitude = location.get("latitude")
        longitude = location.get("longitude")
        address = location.get("address", "Unknown address")
        current_timestamp = datetime.utcnow().isoformat()

        if not username or not mobile or not order_items or not otp:
            return jsonify({'success': False, 'message': 'Incomplete order details!'}), 400

        # ✅ Ensure orderItems use "itemName" instead of "name"
        formatted_items = [
            {
                "itemName": item.get("itemName", "Unknown Item"),
                "price": item.get("price", 0),
                "quantity": item.get("quantity", 1)
            }
            for item in order_items
        ]

        sos_message = f"Order is placed at this location (address: {address}, Latitude: {latitude}, Longitude: {longitude}, mobile: {mobile}, Timestamp: {current_timestamp}) or Track me in map https://www.google.com/maps?q={latitude},{longitude}"

        order_data = {
            "username": username,
            "mobile": mobile,
            "orderItems": formatted_items,
            "selectedSeats": selected_seats,
            "grandTotal": grand_total,
            "otp": otp,
            "location": {
                "latitude": latitude,
                "longitude": longitude,
                "address": address,
                "sos_message": sos_message
            },
            "status": "Pending"
        }

        order_id = orders_collection.insert_one(order_data).inserted_id

        return jsonify({'success': True, 'message': 'Order placed successfully!', 'orderId': str(order_id), "sosMessage": sos_message})

    except Exception as e:
        return jsonify({'success': False, 'message': 'Error processing order.', 'error': str(e)}), 500



@app.route('/get-orders', methods=['POST'])  
def get_orders():
    try:
        data = request.json
        mobile = data.get("mobile")

        if not mobile:
            return jsonify({'success': False, 'message': 'Mobile number is required!'}), 400

        # Fetch orders including orderItems
        orders = list(orders_collection.find(
            {"mobile": mobile},
            {"_id": 1, "username": 1, "mobile": 1, "grandTotal": 1, "status": 1, "orderItems": 1}
        ))

        # Ensure orderItems is always an array and keep "itemName" as it is
        for order in orders:
            order["_id"] = str(order["_id"])  # Convert ObjectId to string
            order["orderItems"] = order.get("orderItems", [])

        print("Fetched Orders:", orders)

        return jsonify({'success': True, 'orders': orders})

    except Exception as e:
        return jsonify({'success': False, 'message': 'Error fetching orders.', 'error': str(e)}), 500



@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    try:
        data = request.json
        order_id = data.get("orderId")
        entered_otp = str(data.get("otp"))  # Convert OTP to string

        if not order_id or not entered_otp:
            return jsonify({'success': False, 'message': 'Order ID and OTP are required!'}), 400

        # Validate ObjectId
        try:
            order_obj_id = ObjectId(order_id)
        except Exception:
            return jsonify({'success': False, 'message': 'Invalid Order ID format!'}), 400

        # Fetch order from the database
        order = orders_collection.find_one({"_id": order_obj_id})
        if not order:
            return jsonify({'success': False, 'message': 'Order not found!'}), 404

        # Get stored OTP as a string
        stored_otp = str(order.get("otp", ""))
        if not stored_otp:
            return jsonify({'success': False, 'message': 'No OTP found for this order!'}), 400

        # Compare entered OTP with stored OTP
        if entered_otp == stored_otp:
            # ✅ DELETE order from database
            delete_result = orders_collection.delete_one({"_id": order_obj_id})

            if delete_result.deleted_count == 1:
                return jsonify({'success': True, 'message': 'OTP verified! Order has been deleted.'})
            else:
                return jsonify({'success': False, 'message': 'Failed to delete order.'}), 500
        else:
            return jsonify({'success': False, 'message': 'Invalid OTP. Please try again.'}), 400

    except Exception as e:
        return jsonify({'success': False, 'message': 'Error verifying OTP.', 'error': str(e)}), 500

               


@app.route('/book', methods=['POST'])
def book_tickets():
    if request.method == 'POST':
        # Retrieve booking data from the request
        username = request.json.get('username')
        selected_seats = request.json.get('selectedSeats', [])
        ticket_number = request.json.get('ticketNumber')
        amount = request.json.get('amount')
        booked_date = request.json.get('bookedDate')

        if not username or not selected_seats:
            return jsonify({'success': False, 'message': 'All fields are required!'})

        # Check if any of the selected seats are already booked
        booked_seats = booked_seats_collection.find({
            'seat': {'$in': selected_seats}
        })

        already_booked = [seat['seat'] for seat in booked_seats]
        if already_booked:
            return jsonify({
                'success': False,
                'message': f'Some seats are already booked: {", ".join(already_booked)}',
                'bookedSeats': already_booked
            })

        # Insert booking data into MongoDB
        booking_data = [
            {
                'username': username,
                'seat': seat,
                'ticketNumber': ticket_number,
                'amount': amount,
                'bookedDate': booked_date
            }
            for seat in selected_seats
        ]

        # Store each seat in the booked_seats_collection
        booked_seats_collection.insert_many(booking_data)

        return jsonify({'success': True, 'message': 'Booking successful!', 'ticketNumber': ticket_number})

    return jsonify({'success': False, 'message': 'Invalid request method.'})
    

@app.route('/check-seats', methods=['POST'])
def check_seats():
    try:
        # Get selected seats from the request body
        data = request.json
        selected_seats = data.get("selectedSeats", [])

        if not selected_seats:
            return jsonify({'success': False, 'message': 'No seats provided for checking.'}), 400

        # Find already booked seats
        booked_seats = booked_seats_collection.find(
            {"seat": {"$in": selected_seats}}
        )

        # Extract booked seat numbers
        booked_seat_list = [seat['seat'] for seat in booked_seats]

        return jsonify({
            'success': True,
            'bookedSeats': booked_seat_list
        })

    except Exception as e:
        return jsonify({'success': False, 'message': 'Error checking seats.', 'error': str(e)}), 500


@app.route('/booked_seats', methods=['GET'])
def get_booked_seats():
    try:
        username = request.args.get('username')  # Get username from query parameters (optional)

        # ✅ If username is provided, filter by username, else return all booked seats
        query = {"username": username} if username else {}

        booked_seats_cursor = booked_seats_collection.find(query, {"_id": 0, "seat": 1})
        booked_seat_numbers = [seat['seat'] for seat in booked_seats_cursor if 'seat' in seat]  # ✅ Ensure valid data

        print("Booked Seats:", booked_seat_numbers)  # ✅ Debugging log

        return jsonify({'success': True, 'bookedSeats': booked_seat_numbers})

    except Exception as e:
        return jsonify({'success': False, 'message': 'Error retrieving booked seats.', 'error': str(e)}), 500





@app.route('/community')
def community():
    username = session.get('username', 'Guest')  # Get the username from the session
    logger.info(f"Community page accessed by {username}.")
    return jsonify({"username": username})

@app.route('/getMessages', methods=['GET'])
def get_messages():
    messages = list(messages_collection.find({}, {'_id': 0}))
    messages_list = []
    for msg in messages:
        message_data = {
            "username": msg.get('username', 'Image'),
            "male" : msg.get('male','not found'),
            "female" : msg.get('female','not found'),
            "total" : msg.get('total','not found'),
            "type": msg.get('type', 'text'),
            
        }
        if msg.get('type') == 'audio':
            message_data["filename"] = msg.get('filename')
        else:
            message_data["message"] = msg.get('message', '')
        messages_list.append(message_data)
    return jsonify({"messages": messages_list})

# Route to send a text message
@app.route('/sendMessage', methods=['POST'])
def send_message():
    data = request.json
    username = data.get('username', 'Guest')  # Default to 'Guest' if not provided
    new_message = {
        "message": data['message'],
        "username": username,
        "type": "text"
    }
    messages_collection.insert_one(new_message)
    logger.info(f"Text message sent by {username}: {data['message']}")
    return jsonify({"status": "Message sent!"})


# Route to get the username from the session
@app.route('/getUsername', methods=['GET'])
def get_username():
    username = session.get('username', 'Guest')
    return jsonify({"username": username})

# Route to handle SOS messages (triggered when SOS button is pressed)
@app.route('/sendSOS', methods=['POST'])
def send_sos():
    data = request.json
    latitude = data['latitude']
    longitude = data['longitude']
    address = data['address']
    username = data['username']
    mobile = data['mobile']
    timezone = pytz.timezone('Asia/Kolkata')
    current_timestamp = datetime.now(timezone).strftime("%Y-%m-%d %H:%M:%S")
    sos_message = f"Emergency! Please help me at (address: {address}, Latitude: {latitude}, Longitude: {longitude}, mobile: {mobile} Timestamp: {current_timestamp}) or Track me in map https://www.google.com/maps?q={latitude},{longitude}"
    new_message = {
        "message": sos_message,
        "username": username,
        "type": "text"
    }
    messages_collection.insert_one(new_message)
    logger.info(f"SOS message sent by {username}: {sos_message}")
    return jsonify({"status": "SOS sent!"})

  

# Home page route
@app.route('/index')
def index():
    username = session.get('username', 'Guest')
    return render_template('index.html', username=username)

@app.route('/sendSOS2', methods=['POST'])
def send_sos2():
    # Check if image is included in the request
    if 'image' not in request.files:
        return jsonify({"error": "No image uploaded"}), 400

    # Get image and username from the request
    image = request.files['image']
    username = request.form.get('username', 'Guest')
    
    # Set a secure path for saving the file on disk
    filename = secure_filename(image.filename)
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    image.save(save_path)  # Save image to the specified path

    # Optionally, convert image to binary for MongoDB storage
    image_binary = BytesIO()
    image.save(image_binary, format=image.format)
    image_data = base64.b64encode(image_binary.getvalue()).decode('utf-8')
    
    # Create the message entry for MongoDB
    new_message = {
        "message": image_data,
        "username": username,
        "type": "image"
    }
    
    messages_collection.insert_one(new_message)  # Store in MongoDB
    logger.info(f"SOS image message sent by {username} and saved at {save_path}")
    
    return jsonify({"status": "SOS sent with image!"})


@app.route('/get_otp', methods=['POST'])
def get_otp():
    try:
        username = request.form.get('username')
        mobile = request.form.get('mobile')
        email = request.form.get('email')
        password = request.form.get('password')

        if not username or not email or not password:
            return jsonify({'success': False, 'message': 'All fields are required!'})

        # Check existing email
        if users_collection.find_one({"email": email}):
            return jsonify({'success': False, 'message': 'Email already exists! Please log in.'})

        # Remove existing OTP for this email
        otp_collection.delete_one({"email": email})

        # Send OTP
        otp_value = send_otp(email)

        if otp_value is None:
            return jsonify({'success': False, 'message': 'Failed to send OTP. Please try again.'})

        return jsonify({'success': True, 'message': 'OTP sent to your email.'})

    except Exception as e:
        logging.error(f"Error in get_otp: {str(e)}")
        return jsonify({'success': False, 'message': 'Server error occurred.'})

def send_otp(email):
    try:
        otp = random.randint(100000, 999999)
        message_body = f"Your OTP for RailConnect registration is: {otp}"

        sender_email = "railconnect24.7@gmail.com"
        sender_password = "kbik vcem dmzc szre"  # Gmail App Password

        # Email message setup
        msg = MIMEMultipart()
        msg["From"] = sender_email
        msg["To"] = email
        msg["Subject"] = "OTP for RailConnect Registration"
        msg.attach(MIMEText(message_body, "plain"))

        # SMTP Server connection
        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, email, msg.as_string())
        server.quit()

        # Save OTP in database
        otp_collection.insert_one({
            "email": email,
            "otp": otp,
            "created_at": datetime.now(),
            "expires_at": datetime.now() + timedelta(minutes=5)
        })

        return otp  # success

    except Exception as e:
        logging.error(f"OTP Sending Failed: {str(e)}")
        return None


# Route for user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        mobile = request.form.get('mobile')
        guardianNum=request.form.get('guardianNum')
        email = request.form.get('email')
        password = request.form.get('password')
        otp = request.form.get('otp')

        if not username or not email or not password:
            return jsonify({'success': False, 'message': 'All fields are required!'})

        # Check if email already exists
        if users_collection.find_one({'email': email}):
            return jsonify({'success': False, 'message': 'Email already exists! Please log in.'})

        # Retrieve OTP data for the email
        otp_data = otp_collection.find_one({"email": email})

        # Check if otp_data is None (OTP not found for the email)
        if otp_data is None:
            return jsonify({'success': False, 'message': 'No OTP found for this email. Please request a new OTP.'})

        # Ensure the OTP is correct
        if otp_data["otp"] != int(otp):
            return jsonify({'success': False, 'message': 'Invalid OTP.'})

        # Delete the OTP document from the collection
        otp_collection.delete_one({"email": email})

        # Insert new user into MongoDB
        users_collection.insert_one({
            'username': username,
            'mobile': mobile,
            'guardianNum' : guardianNum,
            'email': email,
            'password': password  # Plain text for now as requested
        })

        return jsonify({'success': True, 'message': 'Registration successful! Please log in.'})

    return render_template('registration.html')



@app.route('/forget_password', methods=['GET', 'POST'])
def forget_password():
    if request.method == 'POST':
        email = request.form.get('email')
    if users_collection.find_one({'email': email}):
        otp_collection.delete_one({"email": email})
        otp=fsend_otp(email)
        if otp is None:
            return jsonify({'success': False, 'message': 'Failed to send OTP. Please try again.'})
        else:
            return jsonify({'success': True, 'message': 'OTP sent to your Email.Please check'})
    return jsonify({'success': False, 'message': 'user not registred.Please register'})

def fsend_otp(email):
    otp = random.randint(100000, 999999)  # Generate a 6-digit OTP
    message = f"Your new OTP for RailConnect registration is: {otp}"

    # Email setup
    sender_email = "railconnect24.7@gmail.com"
    sender_password = "kbik vcem dmzc szre"
    # Ensure this is a Google App password

    # Create the email message
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = email
    msg['Subject'] = "OTP for password update in RailConnect"
    msg.attach(MIMEText(message, 'plain'))

    try:
        # Send email using SMTP
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, email, msg.as_string())

        # Store OTP in MongoDB with an expiration time of 5 minutes
        otp_data = {
            "email": email,
            "otp": otp,
            "created_at": datetime.now(),
            "expires_at": datetime.now() + timedelta(minutes=5)
        }
        otp_collection.insert_one(otp_data)
        logging.info("OTP sent and saved successfully.")
        return otp  # Return the OTP if successfully sent

    except smtplib.SMTPException as e:
        logging.error(f"Failed to send OTP: {e}")
        return None  # Return None to indicate failure


@app.route('/validate', methods=['GET', 'POST'])
def validate():
    if request.method == 'POST':
        email = request.form.get('email')
        Newpassword = request.form.get('password')
        otp = request.form.get('otp')

        if not email or not Newpassword or not otp:
            return jsonify({'success': False, 'message': 'All fields are required!'})

        # Check if email already exists
        #if users_collection.find_one({'email': email}):
            #return jsonify({'success': False, 'message': 'Email already exists! Please log in.'})

        # Retrieve OTP data for the email
        otp_data = otp_collection.find_one({"email": email})

        # Check if otp_data is None (OTP not found for the email)
        if otp_data is None:
            return jsonify({'success': False, 'message': 'No OTP found for this email. Please request a new OTP.'})

        # Ensure the OTP is correct
        if otp_data["otp"] != int(otp):
            return jsonify({'success': False, 'message': 'Invalid OTP.'})

        # Delete the OTP document from the collection
        otp_collection.delete_one({"email": email})

        users_collection.update_one(
            { 'email': email },
            { '$set': { 'password': Newpassword } }
        )

        # Insert new user into MongoDB
        

        return jsonify({'success': True, 'message': 'New password updated successful! Please log in.'})

    return render_template('forgetpassword.html')

# Route for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Check if user exists
        user = users_collection.find_one({'email': email})

        if user and password == user['password']:
            session['username'] = user['username']
            session['mobile'] = user['mobile']
            session['guardianNum'] = user['guardianNum']
            
            session.permanent = True  # Set session as permanent
            logger.info(f"User {user['username']} logged in successfully.")
          
            return jsonify({'success': True, 'username': user['username'], 'mobile': user['mobile'],'guardianNum': user['guardianNum']})
        else:
            return jsonify({'success': False, 'message': 'Invalid credentials!'})

    return render_template('login.html')
@app.route('/add_guardianNum', methods=['POST'])
def add_guardianNum():
    try:
        if request.method == 'POST':
            email = request.form['email']
            guardianNum = request.form['guardianNum']
            logger.info(f'your email:{email} your guardianNum:{guardianNum}')
            # Ensure email and guardianNum are provided
            if not email or not guardianNum:
                logger.info(f'no email{email} or guardianNum found {guardianNum}')
                return jsonify({'success': False, 'message': 'Email and Guardian Number are required'}), 400
            
            # Update the user's guardian number
            result = users_collection.update_one(
                {'email': email},
                {'$set': {'guardianNum': guardianNum}}
            )

            if result.matched_count == 0:
                return jsonify({'success': False, 'message': 'User not found'}), 404

            # Retrieve the updated user document
            user = users_collection.find_one({'email': email})
            guardianNum = user.get('guardianNum')

            return jsonify({'success': True, 'message': 'Saved Successfully', 'guardianNum': guardianNum})

    except Exception as e:
        print("Error occurred:", e)
        return jsonify({'success': False, 'message': 'An error occurred, please try again later'}), 500

@app.route('/get_guardianNum', methods=['POST'])
def get_guardianNum():
    email = request.form.get('email')  # Retrieve email from POST request body
    user = users_collection.find_one({'email': email})
    
    if user and 'guardianNum' in user:
        guardianNum = user.get('guardianNum')
    else:
        guardianNum = None
    
    return jsonify({'guardianNum': guardianNum})
        
    

# Logout route to clear the session
@app.route('/logout', methods=['POST', 'GET'])
def logout():
    username = session.get('username', 'Guest')
    session.clear()  # Clear the session
    logger.info(f"User {username} logged out.")
    return redirect(url_for('index'))

@app.route('/nearestPoliceStation', methods=['POST'])
def nearest_police_station():
    data = request.get_json()
    latitude = data.get('latitude')
    longitude = data.get('longitude')

    # Predict the nearest police station using the trained model
    try:
        nearest_police_station.nearest_station = en.inverse_transform(cls.predict([[latitude, longitude]]))
        contact_number = df1.loc[df1['Police_station_name'].str.contains(nearest_police_station.nearest_station[0], case=False, na=False), 'phone_number'].values[0]
        n = contact_number.replace('-', '')  # Clean number
        return jsonify({
            'police_station': nearest_police_station.nearest_station[0],
            'contact_number': n  # Ensure you return the cleaned number
        })
    except Exception as e:
        return jsonify({'error': str(e)})


@app.route('/distanceP', methods=['POST'])
def distance_p():
    data = request.get_json()
    lat1 = data.get('latitude')
    lon1 = data.get('longitude')
    nearest_station = en.inverse_transform(cls.predict([[lat1, lon1]]))[0]
    lat1 = float(lat1)
    lon1 = float(lon1)

    # Get the nearest station name and location
    station_data = df1[df1['Police_station_name'].str.contains(nearest_station, case=False, na=False)]

    lat2 = station_data['latitude'].values[0]
    lon2 = station_data['longitude'].values[0]

    lat1, lon1 = math.radians(lat1), math.radians(lon1)
    lat2, lon2 = math.radians(lat2), math.radians(lon2)

    # Haversine formula
    dlat = lat2 - lat1
    dlon = lon2 - lon1

    a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    R = 6371000  # Earth's radius in meters
    distance = (R * c) / 1000
    distance = round(distance, 2)

    return jsonify({'police_distance': distance})

@app.route('/emergency', methods=['POST'])
def emergency():
    data = request.get_json()
    latitude = data.get('latitude')
    longitude = data.get('longitude')
    address = data.get('address')

    # Log received location and address
    logger.info(f'Received emergency location: Latitude {latitude}, Longitude {longitude}, Address {address}')

    return jsonify({'status': 'success', 'latitude': latitude, 'longitude': longitude, 'address': address})

@app.route('/getCrimeAlert', methods=['GET'])
def get_crime_alert():
    city = request.args.get('city')
    crime_alert = 'low'  # Default value
    for i in range(len(df2)):
        if city.lower() in df2['registeration_circles'][i].lower():
            crime_alert = df2['indicator'][i]
            break
    return jsonify({'alert': crime_alert})
    



# Route to accept review data from the frontend
@app.route('/submit_review', methods=['POST'])
def submit_review():
    # Get the JSON data from the request
    data = request.json

    # Extract data from the JSON payload
    latitude = data.get('latitude')
    longitude = data.get('longitude')
    username = data.get('username')
    review_stars = data.get('review_stars')
    review_text = data.get('review_text')

    # Validate input data
    if latitude is None or longitude is None or review_stars is None or review_text is None:
        return jsonify({"error": "Missing data fields"}), 400

    # Create the new message dictionary
    new_message = {
        "username": username,
        "latitude": latitude,
        "longitude": longitude,
        "review_stars": review_stars,
        "review_text": review_text,
        "type": "text"
    }
    
    # Insert the review into the MongoDB collection
    reviews.insert_one(new_message)

    return jsonify({"message": "Review submitted successfully!"}), 201

@app.route('/get_reviews', methods=['POST', 'GET'])
def get_reviews():
    l=[]
    doc=reviews.find()
    for i in doc:
        i['_id'] = str(i['_id'])
        l.append(i)
    return jsonify(l)
    


# Route to accept review data from the frontend
@app.route('/App_review', methods=['POST'])
def App_review():
    # Get the JSON data from the request
    data = request.json

    # Extract data from the JSON payload
    latitude = data.get('latitude')
    longitude = data.get('longitude')
    username = data.get('username')
    review_stars = data.get('review_stars')
    review_text = data.get('review_text')

    # Validate input data
    if latitude is None or longitude is None or review_stars is None or review_text is None:
        return jsonify({"error": "Missing data fields"}), 400

    # Create the new message dictionary
    new_message = {
        "username": username,
        "latitude": latitude,
        "longitude": longitude,
        "review_stars": review_stars,
        "review_text": review_text,
        "type": "text"
    }
    
    # Insert the review into the MongoDB collection
    App_reviews.insert_one(new_message)

    return jsonify({"message": "Review submitted successfully!"}), 201

# Additional emergency and utility routes (trimmed for brevity)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)









