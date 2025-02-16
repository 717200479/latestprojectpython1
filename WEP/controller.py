import re
import pyotp
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from model import *
from services import UserService, ServiceService

app = Flask(__name__)
app.secret_key = 'your_secret_key'

@app.route('/')
def home() -> str:
    try:
        logger.info("Accessed home page")
        return render_template('index.html')
    except Exception as e:
        logger.error(f"Error rendering home page: {e}")
        flash("حدث خطأ أثناء تحميل الصفحة الرئيسية", "danger")
        return redirect(url_for('login'))

@app.route('/tools_boxes', methods=['GET'])
def tools_boxes() -> str:
    try:
        logger.info("Accessed Tools & Boxes page.")
        return render_template('tools_boxes.html')
    except Exception as e:
        logger.error(f"Error rendering tools & boxes page: {e}")
        flash("حدث خطأ أثناء تحميل صفحة الأدوات والصناديق", "danger")
        return redirect(url_for('home'))

@app.route('/imei_services', methods=['GET', 'POST'])
def imei_services() -> str:
    try:
        if request.method == 'POST':
            device = request.form.get('device', '')
            imei = request.form.get('imei', '')
            
            if not device or not imei:
                flash('يجب ملء جميع الحقول المطلوبة', 'danger')
                return redirect(url_for('imei_services'))
            
            flash('تم تقديم طلب الخدمة بنجاح!', 'success')
            logger.info(f"IMEI service requested for device: {device}, IMEI: {imei}")
            return redirect(url_for('imei_services'))
        
        logger.info("Accessed IMEI services page.")
        return render_template('imei_services.html')
    except Exception as e:
        logger.error(f"Error in IMEI services: {e}")
        flash("حدث خطأ أثناء معالجة طلب الخدمة", "danger")
        return redirect(url_for('home'))

@app.route('/remote', methods=['GET'])
def remote() -> str:
    try:
        logger.info("Accessed remote services page.")
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT DISTINCT brand FROM services')
        brands = cursor.fetchall()
        return render_template('remote.html', brands=brands)
    except sqlite3.Error as e:
        logger.error(f"Error retrieving brands: {e}")
        flash("حدث خطأ أثناء تحميل صفحة الخدمات عن بعد", "danger")
        return redirect(url_for('home'))
    finally:
        conn.close()

@app.route('/services/<brand>', methods=['GET'])
def get_services(brand):
    services = get_services_by_brand(brand)
    services_list = [{'name': service[0], 'description': service[1], 'price': service[2], 'requirements': service[3]} for service in services]
    return jsonify(services_list)

@app.route('/user_details', methods=['GET'])
def user_details():
    if 'user_id' not in session:
        flash('يجب تسجيل الدخول لعرض التفاصيل.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = get_user_by_id(user_id)
    
    if user:
        logger.info(f"Fetched user details for user ID {user_id}")
        return render_template('user_details.html', user=user)
    else:
        flash('لم يتم العثور على المستخدم.', 'danger')
        return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    logger.info("Accessed registration page.")
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        phone = request.form['phone']
        smartphone_services = request.form['smartphone_services']
        
        if len(password) < 8 or not re.search(r'[A-Za-z]', password) or not re.search(r'\d', password) or not re.search(r'[\W_]', password):
            flash('خطأ: يجب أن تتكون كلمة المرور من 8 أحرف على الأقل، وتحتوي على أحرف وأرقام ورموز خاصة.', 'danger')
            return render_template('register.html')

        secret = pyotp.random_base32()  # توليد مفتاح 2FA
        password_hashed = hash_password(password)
        success, message = UserService.register_user(username, password_hashed, email, phone, smartphone_services == 'yes', secret)
        
        if success:
            flash(message, 'success')
            logger.info(f"User registered: {username}")
            return redirect(url_for('login'))
        else:
            flash(message, 'danger')
            logger.warning(f"Registration failed for {username}: User already exists.")

    return render_template('register.html')

@app.route('/setup_2fa', methods=['GET', 'POST'])
def setup_2fa():
    user_id = session.get('user_id')
    if not user_id:
        flash('يجب تسجيل الدخول أولاً', 'danger')
        return redirect(url_for('login'))

    user = get_user_by_id(user_id)
    if request.method == 'POST':
        flash('تم تفعيل التوثيق الثنائي بنجاح!', 'success')
        return redirect(url_for('home'))

    totp = pyotp.TOTP(user.secret)
    qr_code_url = totp.provisioning_uri(name=user.username, issuer='YourAppName')
    return render_template('setup_2fa.html', qr_code_url=qr_code_url)

@app.route('/login', methods=['GET', 'POST'])
def login():
    logger.info("Accessed login page.")
    
    if request.method == 'POST':
        username = request.form['username']
        password = hash_password(request.form['password'])
        
        success, result = UserService.login_user(username, password)
        
        if success:
            session['user_id'] = result[0]
            if result[7]:  # تحقق إذا كان 2FA مفعلًا
                return redirect(url_for('verify_2fa'))
            flash('Logged in successfully!', 'success')
            logger.info(f"User logged in: {username}")
            return redirect(url_for('balance'))
        else:
            flash(result, 'danger')
            logger.warning(f"Login failed for {username}: Invalid credentials.")
    
    return render_template('login.html')

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if request.method == 'POST':
        user_id = session['user_id']
        user = get_user_by_id(user_id)
        totp = pyotp.TOTP(user.secret)

        if totp.verify(request.form['token']):
            session['logged_in'] = True
            return redirect(url_for('balance'))
        else:
            flash('رمز التوثيق غير صحيح!', 'danger')

    return render_template('verify_2fa.html')

@app.route('/increase_credit', methods=['POST'])
def increase_credit():
    logger.info("Accessed credit increase page.")
    
    username = request.form['username']
    password = request.form['password']
    credit_to_add = request.form['credit']

    user = get_user_by_username(username)
    if user and user[2] == hash_password(password):
        update_user_credit(user[0], credit_to_add)
        flash('تم زيادة الرصيد بنجاح!', 'success')
        logger.info(f"Credit increased for user: {username}")
    else:
        flash('اسم المستخدم أو كلمة المرور غير صحيحة!', 'danger')
        logger.warning(f"Credit increase failed for {username}: Invalid credentials.")

    return redirect(url_for('manage_services'))

@app.route('/admin/services', methods=['GET', 'POST'])
def manage_services():
    if request.method == 'POST':
        if 'add' in request.form:
            brand = request.form['brand']
            name = request.form['name']
            price = request.form['price']
            description = request.form['description']
            requirements = request.form['requirements']
            success, message = ServiceService.add_service(brand, name, price, description, requirements)
            flash(message, 'success')
            logger.info(f"Service added: {name}")

        elif 'delete' in request.form:
            service_id = request.form['service_id']
            success, message = ServiceService.delete_service(service_id)
            flash(message, 'success')
            logger.info(f"Service deleted: {service_id}")

        elif 'edit' in request.form:
            service_id = request.form['service_id']
            brand = request.form['brand']
            name = request.form['name']
            price = request.form['price']
            description = request.form['description']
            requirements = request.form['requirements']
            success, message = ServiceService.update_service(service_id, brand, name, price, description, requirements)
            flash(message, 'success')
            logger.info(f"Service updated: {service_id}")

    services = ServiceService.get_all_services()
    users = get_all_users()
    
    return render_template('manage_services.html', services=services, users=users)

@app.route('/balance', methods=['GET'])
def balance():
    if 'user_id' in session:
        user = get_user_by_id(session['user_id'])
        if user:
            return render_template('index.html', balance=user[3])
    return redirect(url_for('login'))

@app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    logger.info("User logged out.")
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)