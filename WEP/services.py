import sqlite3
import re
from model import *


class UserService:
    @staticmethod
    def register_user(username, password, email, phone, is_admin=False):
        # Validate email format
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w{2,4}$', email):
            return False, "صيغة البريد الإلكتروني غير صحيحة!"
            
        # Validate phone number format (Egyptian numbers)
        if not re.match(r'^01[0125][0-9]{8}$', phone):
            return False, "رقم الهاتف يجب أن يكون رقم مصري صحيح (11 رقم)!"
            
        try:
            add_user(username, password, email, phone, is_admin)
            return True, "تم التسجيل بنجاح! يمكنك الآن تسجيل الدخول."
        except sqlite3.IntegrityError:
            return False, "اسم المستخدم أو البريد الإلكتروني موجود بالفعل!"


    @staticmethod
    def login_user(username, password):
        user = get_user_by_username(username)
        if user and user[2] == password:
            return True, user
        return False, "اسم المستخدم أو كلمة المرور غير صحيحة!"

    @staticmethod
    def get_user_details(user_id):
        user = get_user_by_id(user_id)
        if user:
            return True, user
        return False, "لم يتم العثور على المستخدم."

class ServiceService:
    @staticmethod
    def add_service(brand, name, price, description, requirements):
        # Validate service name (letters, numbers, spaces, Arabic chars)
        if not re.match(r'^[\u0600-\u06FF\w\s\-]{3,50}$', name):
            return False, "اسم الخدمة يجب أن يحتوي على أحرف عربية/إنجليزية وأرقام فقط (3-50 حرف)!"
            
        # Validate price format
        if not re.match(r'^\d+(\.\d{1,2})?$', str(price)):
            return False, "السعر يجب أن يكون رقمًا صحيحًا أو عشريًا بحد أقصى منزلتين!"
            
        add_service(brand, name, price, description, requirements)
        return True, "تم إضافة الخدمة بنجاح!"


    @staticmethod
    def delete_service(service_id):
        delete_service(service_id)
        return True, "تم حذف الخدمة بنجاح!"

    @staticmethod
    def update_service(service_id, brand, name, price, description, requirements):
        update_service(service_id, brand, name, price, description, requirements)
        return True, "تم تعديل الخدمة بنجاح!"

    @staticmethod
    def get_all_services():
        return get_all_services()

    @staticmethod
    def register_user(username, password_hashed, email, phone, smartphone_services, secret):
        # اكتب الكود لتسجيل المستخدم مع `secret`
        pass

    @staticmethod
    def login_user(username, password):
        # اكتب الكود لتسجيل الدخول
        pass