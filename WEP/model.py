"""
Database models and operations for the WEP application.

This module handles all database interactions including:
- User management
- Service management
- Database initialization
"""
import sqlite3
import hashlib
import logging
import re



def get_user_by_id(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()

def register_user(username, password_hashed, email, phone, smartphone_services, secret):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password, email, phone, smartphone_services, secret) VALUES (?, ?, ?, ?, ?, ?)",
                       (username, password_hashed, email, phone, smartphone_services, secret))
        conn.commit()
        return True, "تم التسجيل بنجاح!"
    except sqlite3.IntegrityError:
        return False, "اسم المستخدم موجود بالفعل."
    finally:
        conn.close()

# باقي الدوال...

# Configure logging to file
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_db_connection():
    """Create and return a database connection."""
    return sqlite3.connect('users.db')

def init_db():
    """
    Initialize the database by creating necessary tables if they don't exist.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                phone TEXT NOT NULL UNIQUE,
                credit REAL DEFAULT 0,
                is_admin BOOLEAN DEFAULT 0
            )
        ''')
        
        # Create services table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                brand TEXT NOT NULL,
                name TEXT NOT NULL,
                price REAL NOT NULL,
                description TEXT NOT NULL,
                requirements TEXT
            )
        ''')
        
        conn.commit()
        logger.info("Database initialized successfully.")
    except sqlite3.Error as e:
        logger.error(f"Database initialization failed: {e}")
        raise
    finally:
        conn.close()


def hash_password(password: str) -> str:
    """
    Hash a password using SHA-256 algorithm.
    
    Args:
        password: The plain text password to hash
        
    Returns:
        Hashed password as a hex string
    """
    return hashlib.sha256(password.encode()).hexdigest()


def get_user_by_username(username: str) -> tuple:
    """
    Retrieve a user by their username.
    
    Args:
        username: The username to search for
        
    Returns:
        A tuple containing user data or None if not found
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        return cursor.fetchone()
    except sqlite3.Error as e:
        logger.error(f"Error retrieving user {username}: {e}")
        raise
    finally:
        conn.close()


def get_user_by_id(user_id: int) -> tuple:
    """
    Retrieve a user by their ID.
    
    Args:
        user_id: The ID of the user to retrieve
        
    Returns:
        A tuple containing user data or None if not found
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        return cursor.fetchone()
    except sqlite3.Error as e:
        logger.error(f"Error retrieving user ID {user_id}: {e}")
        raise
    finally:
        conn.close()


def get_all_users() -> list:
    """
    Retrieve all users from the database.
    
    Returns:
        A list of tuples containing user data
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT username, email, phone, credit FROM users')
        return cursor.fetchall()
    except sqlite3.Error as e:
        logger.error(f"Error retrieving all users: {e}")
        raise
    finally:
        conn.close()


def get_services_by_brand(brand: str) -> list:
    """
    Retrieve services by brand name.
    
    Args:
        brand: The brand name to filter services by
        
    Returns:
        A list of tuples containing service data
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT name, description, price, requirements FROM services WHERE brand = ?', (brand,))
        return cursor.fetchall()
    except sqlite3.Error as e:
        logger.error(f"Error retrieving services for brand {brand}: {e}")
        raise
    finally:
        conn.close()


def add_user(username: str, password: str, email: str, phone: str, is_admin: bool = False) -> None:
    """
    Add a new user to the database with validation.
    
    Args:
        username: The username (3-20 chars, letters, numbers, underscores)
        password: The password to hash and store
        email: Valid email address
        phone: Valid Egyptian phone number
        is_admin: Whether the user is an admin (default False)
        
    Raises:
        ValueError: If any validation fails
        sqlite3.Error: If database operation fails
    """
    # Validate username (letters, numbers, underscores, 3-20 chars)
    if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        raise ValueError("اسم المستخدم يجب أن يحتوي على أحرف إنجليزية وأرقام وشرطة سفلية فقط (3-20 حرف)")
    
    # Validate email format
    if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w{2,4}$', email):
        raise ValueError("صيغة البريد الإلكتروني غير صحيحة!")
        
    # Validate phone number format (Egyptian numbers)
    if not re.match(r'^01[0125][0-9]{8}$', phone):
        raise ValueError("رقم الهاتف يجب أن يكون رقم يمني صحيح (9 رقم)!")
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (username, password, email, phone, is_admin) VALUES (?, ?, ?, ?, ?)', 
                     (username, hash_password(password), email, phone, is_admin))
        conn.commit()
        logger.info(f"User {username} added successfully")
    except sqlite3.IntegrityError as e:
        logger.error(f"Failed to add user {username}: {e}")
        raise ValueError("اسم المستخدم أو البريد الإلكتروني موجود بالفعل!")
    except sqlite3.Error as e:
        logger.error(f"Database error adding user {username}: {e}")
        raise
    finally:
        conn.close()



def update_user_credit(user_id: int, credit: float) -> None:
    """
    Update a user's credit balance.
    
    Args:
        user_id: The ID of the user to update
        credit: The amount to add to the user's balance
        
    Raises:
        sqlite3.Error: If database operation fails
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET credit = credit + ? WHERE id = ?', (credit, user_id))
        conn.commit()
        logger.info(f"Updated credit for user {user_id} by {credit}")
    except sqlite3.Error as e:
        logger.error(f"Failed to update credit for user {user_id}: {e}")
        raise
    finally:
        conn.close()


def add_service(brand: str, name: str, price: float, description: str, requirements: str) -> None:
    """
    Add a new service to the database with validation.
    
    Args:
        brand: The brand name of the service
        name: The service name (3-50 chars, Arabic/English letters, numbers)
        price: The service price (positive number with max 2 decimal places)
        description: The service description
        requirements: The service requirements
        
    Raises:
        ValueError: If any validation fails
        sqlite3.Error: If database operation fails
    """
    # Validate service name (letters, numbers, spaces, Arabic chars)
    if not re.match(r'^[\u0600-\u06FF\w\s\-]{3,50}$', name):
        raise ValueError("اسم الخدمة يجب أن يحتوي على أحرف عربية/إنجليزية وأرقام فقط (3-50 حرف)!")
        
    # Validate price format
    if not re.match(r'^\d+(\.\d{1,2})?$', str(price)):
        raise ValueError("السعر يجب أن يكون رقمًا صحيحًا أو عشريًا بحد أقصى منزلتين!")
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO services (brand, name, price, description, requirements) VALUES (?, ?, ?, ?, ?)', 
                     (brand, name, price, description, requirements))
        conn.commit()
        logger.info(f"Service {name} added successfully")
    except sqlite3.IntegrityError as e:
        logger.error(f"Failed to add service {name}: {e}")
        raise ValueError("اسم الخدمة موجود بالفعل!")
    except sqlite3.Error as e:
        logger.error(f"Database error adding service {name}: {e}")
        raise
    finally:
        conn.close()



def delete_service(service_id: int) -> None:
    """
    Delete a service from the database.
    
    Args:
        service_id: The ID of the service to delete
        
    Raises:
        sqlite3.Error: If database operation fails
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM services WHERE id = ?', (service_id,))
        conn.commit()
        logger.info(f"Service {service_id} deleted successfully")
    except sqlite3.Error as e:
        logger.error(f"Failed to delete service {service_id}: {e}")
        raise
    finally:
        conn.close()


def update_service(service_id: int, brand: str, name: str, price: float, description: str, requirements: str) -> None:
    """
    Update an existing service in the database.
    
    Args:
        service_id: The ID of the service to update
        brand: The updated brand name
        name: The updated service name
        price: The updated price
        description: The updated description
        requirements: The updated requirements
        
    Raises:
        ValueError: If any validation fails
        sqlite3.Error: If database operation fails
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE services 
            SET brand = ?, name = ?, price = ?, description = ?, requirements = ? 
            WHERE id = ?
        ''', (brand, name, price, description, requirements, service_id))
        conn.commit()
        logger.info(f"Service {service_id} updated successfully")
    except sqlite3.Error as e:
        logger.error(f"Failed to update service {service_id}: {e}")
        raise
    finally:
        conn.close()


def get_all_services() -> list:
    """
    Retrieve all services from the database.
    
    Returns:
        A list of tuples containing all service data
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM services')
        services = cursor.fetchall()
        logger.info("Retrieved all services successfully")
        return services
    except sqlite3.Error as e:
        logger.error(f"Failed to retrieve services: {e}")
        raise
    finally:
        conn.close()

# model.py
def get_user_by_id(user_id: int) -> tuple:
    """
    Retrieve a user by their ID.
    
    Args:
        user_id: The ID of the user to retrieve
        
    Returns:
        A tuple containing user data or None if not found
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT username, email, phone, credit FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        logger.info(f"Retrieved user {user_id} successfully")
        return user
    except sqlite3.Error as e:
        logger.error(f"Failed to retrieve user {user_id}: {e}")
        raise
    finally:
        conn.close()
