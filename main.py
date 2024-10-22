import tkinter as tk
from tkinter import messagebox, ttk, filedialog
import sqlite3
import bcrypt
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from PIL import Image, ImageTk
import barcode
from barcode.writer import ImageWriter
import io
import logging
import datetime
import os
from cryptography.fernet import Fernet
import re  # For password validation
import time  # For cooldown implementation

# Setup logging configuration
logging.basicConfig(filename='ims.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Encryption key setup using Fernet symmetric encryption
if not os.path.exists('key.key'):
    # Generate a new key and save it if it doesn't exist
    key = Fernet.generate_key()
    with open('key.key', 'wb') as key_file:
        key_file.write(key)
else:
    # Load the existing key
    with open('key.key', 'rb') as key_file:
        key = key_file.read()

# Create a Fernet object for encryption and decryption
fernet = Fernet(key)

# Database setup using SQLite
conn = sqlite3.connect('inventory_encrypted.db')
cursor = conn.cursor()

def create_tables():
    """
    Create database tables if they do not exist.
    """
    # Users table to store user credentials and roles
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            email TEXT,
            failed_attempts INTEGER DEFAULT 0,
            lockout_time REAL DEFAULT 0
        )
    """)
    # Products table to store product information
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sku TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            description TEXT,
            category TEXT,
            subcategory TEXT,
            attributes TEXT,
            quantity INTEGER NOT NULL,
            location TEXT,
            reorder_point INTEGER,
            price REAL NOT NULL,
            barcode BLOB,
            serial_numbers TEXT,
            lot_number TEXT,
            expiration_date TEXT
        )
    """)
    # Vendors table to store vendor information
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vendors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            contact TEXT,
            email TEXT,
            address TEXT,
            pricing_info TEXT,
            lead_time INTEGER
        )
    """)
    # Purchase orders table to manage purchase orders
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS purchase_orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vendor_id INTEGER,
            product_id INTEGER,
            quantity INTEGER,
            total_price REAL,
            status TEXT,
            date_ordered TEXT,
            date_received TEXT,
            FOREIGN KEY(vendor_id) REFERENCES vendors(id),
            FOREIGN KEY(product_id) REFERENCES products(id)
        )
    """)
    # Inventory movements table to track inventory changes
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS inventory_movements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER,
            change INTEGER,
            date TEXT,
            user_id INTEGER,
            location TEXT,
            FOREIGN KEY(product_id) REFERENCES products(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
    # Audit trail table for logging user actions
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_trail (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT,
            timestamp TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
    conn.commit()

# Create database tables
create_tables()

def create_admin_user():
    """
    Create an initial admin user if it doesn't exist.
    """
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        # Hash the default password 'Admin@123'
        hashed_pw = bcrypt.hashpw('Admin@123'.encode('utf-8'), bcrypt.gensalt())
        # Insert the admin user into the users table
        cursor.execute("INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
                       ('admin', hashed_pw, 'admin', 'admin@example.com'))
        conn.commit()

# Create the initial admin user
create_admin_user()

class InventoryManagementSystem:
    """
    Main class for the Inventory Management System application.
    """

    def __init__(self, root):
        """
        Initialize the application.
        :param root: The root Tkinter window.
        """
        self.root = root
        self.root.title("Inventory Management System")
        self.current_user = None
        # List of locations for multi-location management
        self.locations = ['Warehouse A', 'Warehouse B', 'Store 1', 'Store 2']
        self.failed_login_attempts = {}
        self.login_window()

    def login_window(self):
        """
        Display the login window.
        """
        self.clear_window()
        self.root.geometry("350x300")
        self.root.resizable(False, False)

        # Login label
        tk.Label(self.root, text="Login", font=("Arial", 20)).pack(pady=20)

        # Frame for username and password fields
        frame = tk.Frame(self.root)
        frame.pack(pady=10)

        # Username field
        tk.Label(frame, text="Username:", font=("Arial", 12)).grid(
            row=0, column=0, sticky=tk.E, padx=5, pady=5)
        self.entry_username = tk.Entry(frame, font=("Arial", 12))
        self.entry_username.grid(row=0, column=1, padx=5, pady=5)

        # Password field
        tk.Label(frame, text="Password:", font=("Arial", 12)).grid(
            row=1, column=0, sticky=tk.E, padx=5, pady=5)
        self.entry_password = tk.Entry(frame, show='*', font=("Arial", 12))
        self.entry_password.grid(row=1, column=1, padx=5, pady=5)

        # Login button
        tk.Button(self.root, text="Login", command=self.login,
                  width=10, font=("Arial", 12)).pack(pady=10)
        # Forgot password button
        tk.Button(self.root, text="Forgot Password?",
                  command=self.forgot_password_window, font=("Arial", 10)).pack()

    def login(self):
        """
        Handle user login with account lockout after multiple failed attempts.
        """
        username = self.entry_username.get()
        password = self.entry_password.get()

        if username and password:
            # Fetch user details from the database
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            if user:
                # Check if account is locked
                lockout_time = user[6]
                current_time = time.time()
                if lockout_time > current_time:
                    remaining = int(lockout_time - current_time)
                    messagebox.showerror("Account Locked",
                                         f"Account is locked. Try again in {remaining} seconds.")
                    return

                # Verify password
                if bcrypt.checkpw(password.encode('utf-8'), user[2]):
                    # Reset failed attempts
                    cursor.execute("UPDATE users SET failed_attempts = 0, lockout_time = 0 WHERE username = ?", (username,))
                    conn.commit()
                    # Set the current user
                    self.current_user = {'id': user[0], 'username': user[1], 'role': user[3]}
                    logging.info(f"User {username} logged in.")
                    self.insert_audit_trail('Login')
                    self.main_window()
                else:
                    # Increment failed attempts
                    failed_attempts = user[5] + 1
                    lockout_time = 0
                    if failed_attempts >= 5:
                        lockout_time = time.time() + 300  # Lock account for 5 minutes
                        messagebox.showerror("Account Locked",
                                             "Too many failed attempts. Account is locked for 5 minutes.")
                    else:
                        messagebox.showerror("Error", "Invalid username or password.")
                    # Update failed attempts and lockout time
                    cursor.execute("UPDATE users SET failed_attempts = ?, lockout_time = ? WHERE username = ?",
                                   (failed_attempts, lockout_time, username))
                    conn.commit()
                    logging.warning(f"Failed login attempt for username: {username}")
            else:
                messagebox.showerror("Error", "Invalid username or password.")
        else:
            messagebox.showerror("Error", "Please enter your username and password.")

    def forgot_password_window(self):
        """
        Display the forgot password window with email verification.
        """
        self.clear_window()
        self.root.geometry("400x300")

        tk.Label(self.root, text="Reset Password", font=("Arial", 20)).pack(pady=20)

        frame = tk.Frame(self.root)
        frame.pack(pady=10)

        # Username field for password reset
        tk.Label(frame, text="Username:", font=("Arial", 12)).grid(
            row=0, column=0, sticky=tk.E, padx=5, pady=5)
        self.entry_reset_username = tk.Entry(frame, font=("Arial", 12))
        self.entry_reset_username.grid(row=0, column=1, padx=5, pady=5)

        # Email field for verification
        tk.Label(frame, text="Email:", font=("Arial", 12)).grid(
            row=1, column=0, sticky=tk.E, padx=5, pady=5)
        self.entry_reset_email = tk.Entry(frame, font=("Arial", 12))
        self.entry_reset_email.grid(row=1, column=1, padx=5, pady=5)

        # New password field
        tk.Label(frame, text="New Password:", font=("Arial", 12)).grid(
            row=2, column=0, sticky=tk.E, padx=5, pady=5)
        self.entry_reset_password = tk.Entry(frame, show='*', font=("Arial", 12))
        self.entry_reset_password.grid(row=2, column=1, padx=5, pady=5)

        # Reset password button
        tk.Button(self.root, text="Reset Password", command=self.reset_password,
                  width=15, font=("Arial", 12)).pack(pady=10)
        # Back to login button
        tk.Button(self.root, text="Back to Login",
                  command=self.login_window, font=("Arial", 10)).pack()

    def reset_password(self):
        """
        Handle password reset functionality with email verification.
        """
        username = self.entry_reset_username.get()
        email = self.entry_reset_email.get()
        new_password = self.entry_reset_password.get()

        if username and email and new_password:
            # Check if the username and email exist
            cursor.execute("SELECT * FROM users WHERE username = ? AND email = ?", (username, email))
            user = cursor.fetchone()
            if user:
                if not self.validate_password_strength(new_password):
                    return
                # Update the password
                hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                cursor.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_pw, username))
                conn.commit()
                messagebox.showinfo("Success", "Password reset successfully!")
                logging.info(f"Password reset for username: {username}")
                self.login_window()
            else:
                messagebox.showerror("Error", "Username and email do not match.")
                logging.warning(f"Password reset attempt failed for username: {username}")
        else:
            messagebox.showerror("Error", "Please fill in all fields.")

    def main_window(self):
        """
        Display the main application window after successful login.
        """
        self.clear_window()
        self.root.geometry("1200x700")
        self.root.resizable(True, True)

        # Menu Bar setup
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File Menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label='File', menu=file_menu)
        file_menu.add_command(label='Import Data', command=self.import_data)
        file_menu.add_command(label='Export Data', command=self.export_data)
        file_menu.add_separator()
        file_menu.add_command(label='Logout', command=self.logout)
        file_menu.add_command(label='Exit', command=self.root.quit)

        # Admin Menu for users with admin role
        if self.current_user['role'] == 'admin':
            admin_menu = tk.Menu(menubar, tearoff=0)
            menubar.add_cascade(label='Admin', menu=admin_menu)
            admin_menu.add_command(label='Manage Users', command=self.manage_users)
            admin_menu.add_command(label='Create New User', command=self.create_user_window)
            admin_menu.add_command(label='View Audit Trail', command=self.view_audit_trail)

        # Tab Control setup
        tab_control = ttk.Notebook(self.root)
        self.product_tab = ttk.Frame(tab_control)
        self.vendor_tab = ttk.Frame(tab_control)
        self.purchase_order_tab = ttk.Frame(tab_control)
        self.report_tab = ttk.Frame(tab_control)

        # Adding tabs to the notebook
        tab_control.add(self.product_tab, text='Products')
        tab_control.add(self.vendor_tab, text='Vendors')
        tab_control.add(self.purchase_order_tab, text='Purchase Orders')
        tab_control.add(self.report_tab, text='Reports')

        tab_control.pack(expand=1, fill='both')

        # Initialize each tab
        self.init_product_tab()
        self.init_vendor_tab()
        self.init_purchase_order_tab()
        self.init_report_tab()

    # =========================== Product Tab ===========================
    def init_product_tab(self):
        """
        Initialize the Products tab.
        """
        # Left Frame for the product form
        form_frame = tk.Frame(self.product_tab)
        form_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)

        tk.Label(form_frame, text="Product Details", font=("Arial", 14)).pack(pady=5)

        self.product_fields = {}
        # Fields for product details
        fields = ['SKU', 'Name', 'Description', 'Category', 'Subcategory',
                  'Attributes', 'Quantity', 'Location', 'Reorder Point',
                  'Price', 'Serial Numbers', 'Lot Number', 'Expiration Date']
        for field in fields:
            frame = tk.Frame(form_frame)
            frame.pack(fill=tk.X, pady=2)
            tk.Label(frame, text=field, width=15).pack(side=tk.LEFT)
            if field == 'Location':
                # Location field as a dropdown
                entry = ttk.Combobox(frame, values=self.locations, state='readonly')
            elif field == 'Expiration Date':
                # Placeholder for expiration date
                entry = tk.Entry(frame)
                entry.insert(0, 'YYYY-MM-DD')
            else:
                entry = tk.Entry(frame)
            entry.pack(fill=tk.X, padx=5)
            self.product_fields[field.lower().replace(' ', '_')] = entry

        # Barcode image display
        self.barcode_image_label = tk.Label(form_frame)
        self.barcode_image_label.pack(pady=10)

        # Action buttons for product operations
        btn_frame = tk.Frame(form_frame)
        btn_frame.pack(pady=10)

        tk.Button(btn_frame, text="Add Product", command=self.add_product).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Update Product", command=self.update_product).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Delete Product", command=self.delete_product).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Clear Fields", command=self.clear_product_fields).pack(side=tk.LEFT, padx=5)

        # Right Frame for the product list
        list_frame = tk.Frame(self.product_tab)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Search bar for products
        search_frame = tk.Frame(list_frame)
        search_frame.pack(fill=tk.X)

        tk.Label(search_frame, text="Search").pack(side=tk.LEFT)
        self.entry_product_search = tk.Entry(search_frame)
        self.entry_product_search.pack(side=tk.LEFT, padx=5)
        tk.Button(search_frame, text="Search", command=self.search_products).pack(side=tk.LEFT)
        tk.Button(search_frame, text="Show All", command=self.load_products).pack(side=tk.LEFT, padx=5)

        # Treeview to display products
        columns = ("ID", "SKU", "Name", "Category", "Quantity", "Location", "Price")
        self.product_tree = ttk.Treeview(list_frame, columns=columns, show='headings')
        for col in columns:
            self.product_tree.heading(col, text=col)
            self.product_tree.column(col, anchor=tk.CENTER)

        # Scrollbar for the product list
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.product_tree.yview)
        self.product_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.product_tree.pack(fill=tk.BOTH, expand=True)
        self.product_tree.bind('<ButtonRelease-1>', self.select_product)

        # Load products into the treeview
        self.load_products()

    def add_product(self):
        """
        Add a new product to the inventory.
        """
        # Retrieve data from form fields
        sku = self.product_fields['sku'].get()
        name = self.product_fields['name'].get()
        description = self.product_fields['description'].get()
        category = self.product_fields['category'].get()
        subcategory = self.product_fields['subcategory'].get()
        attributes = self.product_fields['attributes'].get()
        quantity = self.product_fields['quantity'].get()
        location = self.product_fields['location'].get()
        reorder_point = self.product_fields['reorder_point'].get()
        price = self.product_fields['price'].get()
        serial_numbers = self.product_fields['serial_numbers'].get()
        lot_number = self.product_fields['lot_number'].get()
        expiration_date = self.product_fields['expiration_date'].get()

        if sku and name and quantity and price:
            try:
                # Convert quantity and price to appropriate data types
                quantity = int(quantity)
                price = float(price)
                reorder_point = int(reorder_point) if reorder_point else None
                # Generate barcode image
                barcode_img = self.generate_barcode(sku)
                # Insert product into the database
                cursor.execute("""
                    INSERT INTO products (sku, name, description, category, subcategory,
                    attributes, quantity, location, reorder_point, price, barcode,
                    serial_numbers, lot_number, expiration_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (sku, name, description, category, subcategory, attributes, quantity,
                      location, reorder_point, price, barcode_img, serial_numbers, lot_number,
                      expiration_date))
                conn.commit()
                messagebox.showinfo("Success", "Product added successfully!")
                logging.info(f"Product added: {name} (SKU: {sku})")
                self.insert_audit_trail(f"Added product {name} (SKU: {sku})")
                self.load_products()
                self.clear_product_fields()
            except sqlite3.IntegrityError:
                messagebox.showerror("Error", "SKU must be unique.")
                logging.error(f"Failed to add product with duplicate SKU: {sku}")
            except ValueError:
                messagebox.showerror("Error", "Please enter valid numerical values for Quantity and Price.")
        else:
            messagebox.showerror("Error", "Please fill in all required fields.")

    def update_product(self):
        """
        Update the selected product's details.
        """
        selected = self.product_tree.focus()
        if selected:
            product_id = self.product_tree.item(selected)['values'][0]
            # Retrieve data from form fields
            sku = self.product_fields['sku'].get()
            name = self.product_fields['name'].get()
            description = self.product_fields['description'].get()
            category = self.product_fields['category'].get()
            subcategory = self.product_fields['subcategory'].get()
            attributes = self.product_fields['attributes'].get()
            quantity = self.product_fields['quantity'].get()
            location = self.product_fields['location'].get()
            reorder_point = self.product_fields['reorder_point'].get()
            price = self.product_fields['price'].get()
            serial_numbers = self.product_fields['serial_numbers'].get()
            lot_number = self.product_fields['lot_number'].get()
            expiration_date = self.product_fields['expiration_date'].get()

            if sku and name and quantity and price:
                try:
                    # Convert quantity and price to appropriate data types
                    quantity = int(quantity)
                    price = float(price)
                    reorder_point = int(reorder_point) if reorder_point else None
                    # Generate barcode image
                    barcode_img = self.generate_barcode(sku)
                    # Update product in the database
                    cursor.execute("""
                        UPDATE products
                        SET sku = ?, name = ?, description = ?, category = ?, subcategory = ?,
                        attributes = ?, quantity = ?, location = ?, reorder_point = ?, price = ?,
                        barcode = ?, serial_numbers = ?, lot_number = ?, expiration_date = ?
                        WHERE id = ?
                    """, (sku, name, description, category, subcategory, attributes, quantity,
                          location, reorder_point, price, barcode_img, serial_numbers, lot_number,
                          expiration_date, product_id))
                    conn.commit()
                    messagebox.showinfo("Success", "Product updated successfully!")
                    logging.info(f"Product updated: {name} (ID: {product_id})")
                    self.insert_audit_trail(f"Updated product {name} (ID: {product_id})")
                    self.load_products()
                    self.clear_product_fields()
                except sqlite3.IntegrityError:
                    messagebox.showerror("Error", "SKU must be unique.")
                    logging.error(f"Failed to update product with duplicate SKU: {sku}")
                except ValueError:
                    messagebox.showerror("Error", "Please enter valid numerical values for Quantity and Price.")
            else:
                messagebox.showerror("Error", "Please fill in all required fields.")
        else:
            messagebox.showerror("Error", "Please select a product to update.")

    def delete_product(self):
        """
        Delete the selected product from the inventory.
        """
        # Check user role for permission
        if self.current_user['role'] not in ['admin', 'manager']:
            messagebox.showerror("Error", "Only admins and managers can delete products.")
            return
        selected = self.product_tree.focus()
        if selected:
            product_id = self.product_tree.item(selected)['values'][0]
            confirm = messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this product?")
            if confirm:
                # Delete product from the database
                cursor.execute("DELETE FROM products WHERE id = ?", (product_id,))
                conn.commit()
                messagebox.showinfo("Success", "Product deleted successfully!")
                logging.info(f"Product deleted (ID: {product_id})")
                self.insert_audit_trail(f"Deleted product (ID: {product_id})")
                self.load_products()
                self.clear_product_fields()
        else:
            messagebox.showerror("Error", "Please select a product to delete.")

    def load_products(self, query="""
        SELECT id, sku, name, category, quantity, location, price FROM products
    """, params=()):
        """
        Load products into the treeview.
        :param query: SQL query to fetch products.
        :param params: Parameters for the SQL query.
        """
        # Clear existing products from the treeview
        for item in self.product_tree.get_children():
            self.product_tree.delete(item)
        # Execute the query and insert products into the treeview
        cursor.execute(query, params)
        for row in cursor.fetchall():
            self.product_tree.insert('', 'end', values=row)
        # Check for products that have reached their reorder points
        self.check_reorder_points()

    def search_products(self):
        """
        Search for products based on the keyword entered.
        """
        keyword = self.entry_product_search.get()
        query = """
            SELECT id, sku, name, category, quantity, location, price FROM products
            WHERE sku LIKE ? OR name LIKE ? OR category LIKE ?
        """
        params = ('%' + keyword + '%', '%' + keyword + '%', '%' + keyword + '%')
        self.load_products(query, params)

    def select_product(self, event):
        """
        Select a product from the treeview and display its details.
        :param event: The event object.
        """
        selected = self.product_tree.focus()
        if selected:
            values = self.product_tree.item(selected, 'values')
            self.clear_product_fields()
            # Fetch product details from the database
            cursor.execute("SELECT * FROM products WHERE id = ?", (values[0],))
            product = cursor.fetchone()
            columns = [description[0] for description in cursor.description]
            product_data = dict(zip(columns, product))
            # Populate form fields with product data
            for field in self.product_fields:
                value = product_data.get(field)
                if value is not None:
                    self.product_fields[field].delete(0, tk.END)
                    self.product_fields[field].insert(0, str(value))
            # Display the barcode image
            barcode_data = product_data.get('barcode')
            if barcode_data:
                image = Image.open(io.BytesIO(barcode_data))
                image = image.resize((200, 100), Image.ANTIALIAS)
                photo = ImageTk.PhotoImage(image)
                self.barcode_image_label.config(image=photo)
                self.barcode_image_label.image = photo

    def clear_product_fields(self):
        """
        Clear all product form fields.
        """
        for field in self.product_fields.values():
            if isinstance(field, ttk.Combobox):
                field.set('')
            else:
                field.delete(0, tk.END)
        # Clear the barcode image
        self.barcode_image_label.config(image='')

    def generate_barcode(self, sku):
        """
        Generate a barcode image for the given SKU.
        :param sku: The SKU of the product.
        :return: The barcode image in bytes.
        """
        barcode_class = barcode.get_barcode_class('code128')
        my_barcode = barcode_class(sku, writer=ImageWriter())
        buffer = io.BytesIO()
        my_barcode.write(buffer)
        barcode_img = buffer.getvalue()
        buffer.close()
        return barcode_img

    def check_reorder_points(self):
        """
        Check if any products have reached their reorder points and alert the user.
        """
        cursor.execute("SELECT sku, name, quantity, reorder_point FROM products")
        products = cursor.fetchall()
        for product in products:
            sku, name, quantity, reorder_point = product
            if reorder_point and quantity <= reorder_point:
                messagebox.showwarning("Reorder Alert",
                                       f"Product {name} (SKU: {sku}) has reached its reorder point.")

    # =========================== Vendor Tab ===========================
    def init_vendor_tab(self):
        """
        Initialize the Vendors tab.
        """
        # Left Frame for the vendor form
        form_frame = tk.Frame(self.vendor_tab)
        form_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)

        tk.Label(form_frame, text="Vendor Details", font=("Arial", 14)).pack(pady=5)

        self.vendor_fields = {}
        # Fields for vendor details
        fields = ['Name', 'Contact', 'Email', 'Address', 'Pricing Info', 'Lead Time']
        for field in fields:
            frame = tk.Frame(form_frame)
            frame.pack(fill=tk.X, pady=2)
            tk.Label(frame, text=field, width=12).pack(side=tk.LEFT)
            entry = tk.Entry(frame)
            entry.pack(fill=tk.X, padx=5)
            self.vendor_fields[field.lower().replace(' ', '_')] = entry

        # Action buttons for vendor operations
        btn_frame = tk.Frame(form_frame)
        btn_frame.pack(pady=10)

        tk.Button(btn_frame, text="Add Vendor", command=self.add_vendor).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Update Vendor", command=self.update_vendor).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Delete Vendor", command=self.delete_vendor).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Clear Fields", command=self.clear_vendor_fields).pack(side=tk.LEFT, padx=5)

        # Right Frame for the vendor list
        list_frame = tk.Frame(self.vendor_tab)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Search bar for vendors
        search_frame = tk.Frame(list_frame)
        search_frame.pack(fill=tk.X)

        tk.Label(search_frame, text="Search").pack(side=tk.LEFT)
        self.entry_vendor_search = tk.Entry(search_frame)
        self.entry_vendor_search.pack(side=tk.LEFT, padx=5)
        tk.Button(search_frame, text="Search", command=self.search_vendors).pack(side=tk.LEFT)
        tk.Button(search_frame, text="Show All", command=self.load_vendors).pack(side=tk.LEFT, padx=5)

        # Treeview to display vendors
        columns = ("ID", "Name", "Contact", "Email", "Lead Time")
        self.vendor_tree = ttk.Treeview(list_frame, columns=columns, show='headings')
        for col in columns:
            self.vendor_tree.heading(col, text=col)
            self.vendor_tree.column(col, anchor=tk.CENTER)

        # Scrollbar for the vendor list
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.vendor_tree.yview)
        self.vendor_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.vendor_tree.pack(fill=tk.BOTH, expand=True)
        self.vendor_tree.bind('<ButtonRelease-1>', self.select_vendor)

        # Load vendors into the treeview
        self.load_vendors()

    def add_vendor(self):
        """
        Add a new vendor to the system.
        """
        # Retrieve data from form fields
        name = self.vendor_fields['name'].get()
        contact = self.vendor_fields['contact'].get()
        email = self.vendor_fields['email'].get()
        address = self.vendor_fields['address'].get()
        pricing_info = self.vendor_fields['pricing_info'].get()
        lead_time = self.vendor_fields['lead_time'].get()

        if name:
            lead_time = int(lead_time) if lead_time else None
            # Insert vendor into the database
            cursor.execute("""
                INSERT INTO vendors (name, contact, email, address, pricing_info, lead_time)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (name, contact, email, address, pricing_info, lead_time))
            conn.commit()
            messagebox.showinfo("Success", "Vendor added successfully!")
            logging.info(f"Vendor added: {name}")
            self.insert_audit_trail(f"Added vendor {name}")
            self.load_vendors()
            self.clear_vendor_fields()
        else:
            messagebox.showerror("Error", "Please fill in the name field.")

    def update_vendor(self):
        """
        Update the selected vendor's details.
        """
        selected = self.vendor_tree.focus()
        if selected:
            vendor_id = self.vendor_tree.item(selected)['values'][0]
            # Retrieve data from form fields
            name = self.vendor_fields['name'].get()
            contact = self.vendor_fields['contact'].get()
            email = self.vendor_fields['email'].get()
            address = self.vendor_fields['address'].get()
            pricing_info = self.vendor_fields['pricing_info'].get()
            lead_time = self.vendor_fields['lead_time'].get()

            if name:
                lead_time = int(lead_time) if lead_time else None
                # Update vendor in the database
                cursor.execute("""
                    UPDATE vendors
                    SET name = ?, contact = ?, email = ?, address = ?, pricing_info = ?, lead_time = ?
                    WHERE id = ?
                """, (name, contact, email, address, pricing_info, lead_time, vendor_id))
                conn.commit()
                messagebox.showinfo("Success", "Vendor updated successfully!")
                logging.info(f"Vendor updated: {name} (ID: {vendor_id})")
                self.insert_audit_trail(f"Updated vendor {name} (ID: {vendor_id})")
                self.load_vendors()
                self.clear_vendor_fields()
            else:
                messagebox.showerror("Error", "Please fill in the name field.")
        else:
            messagebox.showerror("Error", "Please select a vendor to update.")

    def delete_vendor(self):
        """
        Delete the selected vendor from the system.
        """
        selected = self.vendor_tree.focus()
        if selected:
            vendor_id = self.vendor_tree.item(selected)['values'][0]
            confirm = messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this vendor?")
            if confirm:
                # Delete vendor from the database
                cursor.execute("DELETE FROM vendors WHERE id = ?", (vendor_id,))
                conn.commit()
                messagebox.showinfo("Success", "Vendor deleted successfully!")
                logging.info(f"Vendor deleted (ID: {vendor_id})")
                self.insert_audit_trail(f"Deleted vendor (ID: {vendor_id})")
                self.load_vendors()
                self.clear_vendor_fields()
        else:
            messagebox.showerror("Error", "Please select a vendor to delete.")

    def load_vendors(self, query="SELECT id, name, contact, email, lead_time FROM vendors", params=()):
        """
        Load vendors into the treeview.
        :param query: SQL query to fetch vendors.
        :param params: Parameters for the SQL query.
        """
        # Clear existing vendors from the treeview
        for item in self.vendor_tree.get_children():
            self.vendor_tree.delete(item)
        # Execute the query and insert vendors into the treeview
        cursor.execute(query, params)
        for row in cursor.fetchall():
            self.vendor_tree.insert('', 'end', values=row)

    def search_vendors(self):
        """
        Search for vendors based on the keyword entered.
        """
        keyword = self.entry_vendor_search.get()
        query = """
            SELECT id, name, contact, email, lead_time FROM vendors
            WHERE name LIKE ? OR contact LIKE ? OR email LIKE ?
        """
        params = ('%' + keyword + '%', '%' + keyword + '%', '%' + keyword + '%')
        self.load_vendors(query, params)

    def select_vendor(self, event):
        """
        Select a vendor from the treeview and display its details.
        :param event: The event object.
        """
        selected = self.vendor_tree.focus()
        if selected:
            values = self.vendor_tree.item(selected, 'values')
            self.clear_vendor_fields()
            # Fetch vendor details from the database
            cursor.execute("SELECT * FROM vendors WHERE id = ?", (values[0],))
            vendor = cursor.fetchone()
            columns = [description[0] for description in cursor.description]
            vendor_data = dict(zip(columns, vendor))
            # Populate form fields with vendor data
            for field in self.vendor_fields:
                value = vendor_data.get(field)
                if value is not None:
                    self.vendor_fields[field].delete(0, tk.END)
                    self.vendor_fields[field].insert(0, str(value))

    def clear_vendor_fields(self):
        """
        Clear all vendor form fields.
        """
        for field in self.vendor_fields.values():
            field.delete(0, tk.END)

    # =========================== Purchase Order Tab ===========================
    def init_purchase_order_tab(self):
        """
        Initialize the Purchase Orders tab.
        """
        # Left Frame for the purchase order form
        form_frame = tk.Frame(self.purchase_order_tab)
        form_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)

        tk.Label(form_frame, text="Purchase Order Details", font=("Arial", 14)).pack(pady=5)

        self.po_fields = {}

        # Vendor selection field
        frame = tk.Frame(form_frame)
        frame.pack(fill=tk.X, pady=2)
        tk.Label(frame, text="Vendor", width=12).pack(side=tk.LEFT)
        self.po_fields['vendor'] = ttk.Combobox(frame, values=self.get_vendors(), state='readonly')
        self.po_fields['vendor'].pack(fill=tk.X, padx=5)

        # Product selection field
        frame = tk.Frame(form_frame)
        frame.pack(fill=tk.X, pady=2)
        tk.Label(frame, text="Product", width=12).pack(side=tk.LEFT)
        self.po_fields['product'] = ttk.Combobox(frame, values=self.get_products(), state='readonly')
        self.po_fields['product'].pack(fill=tk.X, padx=5)

        # Quantity field
        frame = tk.Frame(form_frame)
        frame.pack(fill=tk.X, pady=2)
        tk.Label(frame, text="Quantity", width=12).pack(side=tk.LEFT)
        self.po_fields['quantity'] = tk.Entry(frame)
        self.po_fields['quantity'].pack(fill=tk.X, padx=5)

        # Action buttons for purchase order operations
        btn_frame = tk.Frame(form_frame)
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Create PO", command=self.create_purchase_order).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Receive PO", command=self.receive_purchase_order).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Clear Fields", command=self.clear_po_fields).pack(side=tk.LEFT, padx=5)

        # Right Frame for the purchase order list
        list_frame = tk.Frame(self.purchase_order_tab)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Search bar for purchase orders
        search_frame = tk.Frame(list_frame)
        search_frame.pack(fill=tk.X)

        tk.Label(search_frame, text="Search").pack(side=tk.LEFT)
        self.entry_po_search = tk.Entry(search_frame)
        self.entry_po_search.pack(side=tk.LEFT, padx=5)
        tk.Button(search_frame, text="Search", command=self.search_purchase_orders).pack(side=tk.LEFT)
        tk.Button(search_frame, text="Show All", command=self.load_purchase_orders).pack(side=tk.LEFT, padx=5)

        # Treeview to display purchase orders
        columns = ("ID", "Vendor", "Product", "Quantity", "Total Price", "Status", "Date Ordered")
        self.po_tree = ttk.Treeview(list_frame, columns=columns, show='headings')
        for col in columns:
            self.po_tree.heading(col, text=col)
            self.po_tree.column(col, anchor=tk.CENTER)

        # Scrollbar for the purchase order list
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.po_tree.yview)
        self.po_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.po_tree.pack(fill=tk.BOTH, expand=True)
        self.po_tree.bind('<ButtonRelease-1>', self.select_purchase_order)

        # Load purchase orders into the treeview
        self.load_purchase_orders()

    def create_purchase_order(self):
        """
        Create a new purchase order.
        """
        vendor_name = self.po_fields['vendor'].get()
        product_name = self.po_fields['product'].get()
        quantity = self.po_fields['quantity'].get()

        if vendor_name and product_name and quantity:
            try:
                quantity = int(quantity)
                # Get vendor ID from the database
                cursor.execute("SELECT id FROM vendors WHERE name = ?", (vendor_name,))
                vendor = cursor.fetchone()
                if not vendor:
                    messagebox.showerror("Error", "Vendor not found.")
                    return
                vendor_id = vendor[0]

                # Get product ID and price from the database
                cursor.execute("SELECT id, price FROM products WHERE name = ?", (product_name,))
                product = cursor.fetchone()
                if not product:
                    messagebox.showerror("Error", "Product not found.")
                    return
                product_id, price = product
                total_price = quantity * price

                # Insert the purchase order into the database
                cursor.execute("""
                    INSERT INTO purchase_orders (vendor_id, product_id, quantity, total_price, status, date_ordered)
                    VALUES (?, ?, ?, ?, ?, DATE('now'))
                """, (vendor_id, product_id, quantity, total_price, 'Ordered'))
                conn.commit()
                messagebox.showinfo("Success", "Purchase order created successfully!")
                logging.info(f"Purchase order created: Product ID {product_id}, Quantity {quantity}")
                self.insert_audit_trail(f"Created purchase order for product ID {product_id}, Quantity {quantity}")
                self.load_purchase_orders()
                self.clear_po_fields()
            except ValueError:
                messagebox.showerror("Error", "Please enter a valid quantity.")
        else:
            messagebox.showerror("Error", "Please fill in all required fields.")

    def receive_purchase_order(self):
        """
        Receive the selected purchase order and update inventory.
        """
        selected = self.po_tree.focus()
        if selected:
            po_id = self.po_tree.item(selected)['values'][0]
            # Fetch purchase order details
            cursor.execute("SELECT status, product_id, quantity FROM purchase_orders WHERE id = ?", (po_id,))
            po = cursor.fetchone()
            if po[0] == 'Received':
                messagebox.showerror("Error", "Purchase order already received.")
                return
            # Update purchase order status to 'Received'
            cursor.execute("""
                UPDATE purchase_orders
                SET status = ?, date_received = DATE('now')
                WHERE id = ?
            """, ('Received', po_id))
            # Update product quantity in the inventory
            cursor.execute("SELECT quantity FROM products WHERE id = ?", (po[1],))
            product_quantity = cursor.fetchone()[0]
            new_quantity = product_quantity + po[2]
            cursor.execute("UPDATE products SET quantity = ? WHERE id = ?", (new_quantity, po[1]))
            conn.commit()
            messagebox.showinfo("Success", "Purchase order received successfully!")
            logging.info(f"Purchase order received (ID: {po_id})")
            self.insert_audit_trail(f"Received purchase order (ID: {po_id})")
            self.load_purchase_orders()
            self.load_products()
        else:
            messagebox.showerror("Error", "Please select a purchase order to receive.")

    def load_purchase_orders(self, query="""
        SELECT po.id, v.name, p.name, po.quantity, po.total_price, po.status, po.date_ordered
        FROM purchase_orders po
        LEFT JOIN vendors v ON po.vendor_id = v.id
        LEFT JOIN products p ON po.product_id = p.id
    """, params=()):
        """
        Load purchase orders into the treeview.
        :param query: SQL query to fetch purchase orders.
        :param params: Parameters for the SQL query.
        """
        # Clear existing purchase orders from the treeview
        for item in self.po_tree.get_children():
            self.po_tree.delete(item)
        # Execute the query and insert purchase orders into the treeview
        cursor.execute(query, params)
        for row in cursor.fetchall():
            self.po_tree.insert('', 'end', values=row)

    def search_purchase_orders(self):
        """
        Search for purchase orders based on the keyword entered.
        """
        keyword = self.entry_po_search.get()
        query = """
            SELECT po.id, v.name, p.name, po.quantity, po.total_price, po.status, po.date_ordered
            FROM purchase_orders po
            LEFT JOIN vendors v ON po.vendor_id = v.id
            LEFT JOIN products p ON po.product_id = p.id
            WHERE v.name LIKE ? OR p.name LIKE ? OR po.status LIKE ?
        """
        params = ('%' + keyword + '%', '%' + keyword + '%', '%' + keyword + '%')
        self.load_purchase_orders(query, params)

    def select_purchase_order(self, event):
        """
        Select a purchase order from the treeview and display its details.
        :param event: The event object.
        """
        selected = self.po_tree.focus()
        if selected:
            values = self.po_tree.item(selected, 'values')
            self.clear_po_fields()
            self.po_fields['vendor'].set(values[1])
            self.po_fields['product'].set(values[2])
            self.po_fields['quantity'].delete(0, tk.END)
            self.po_fields['quantity'].insert(0, values[3])

    def clear_po_fields(self):
        """
        Clear all purchase order form fields.
        """
        for field in self.po_fields.values():
            if isinstance(field, ttk.Combobox):
                field.set('')
            else:
                field.delete(0, tk.END)

    # =========================== Report Tab ===========================
    def init_report_tab(self):
        """
        Initialize the Reports tab.
        """
        tk.Label(self.report_tab, text="Reports and Analytics", font=("Arial", 16)).pack(pady=10)

        btn_frame = tk.Frame(self.report_tab)
        btn_frame.pack(pady=20)

        # Buttons to generate different reports
        tk.Button(btn_frame, text="Inventory Report", command=self.inventory_report, width=20).pack(pady=5)
        tk.Button(btn_frame, text="Reorder Report", command=self.reorder_report, width=20).pack(pady=5)
        tk.Button(btn_frame, text="Vendor Report", command=self.vendor_report, width=20).pack(pady=5)

    def inventory_report(self):
        """
        Generate and display an inventory report.
        """
        # Fetch data for the report
        cursor.execute("SELECT category, SUM(quantity) FROM products GROUP BY category")
        data = cursor.fetchall()
        categories = [row[0] for row in data]
        quantities = [row[1] for row in data]

        if not categories:
            messagebox.showinfo("Information", "No data available for reporting.")
            return

        # Create a new window for the report
        report_window = tk.Toplevel(self.root)
        report_window.title("Inventory Report")
        report_window.geometry("700x500")

        # Generate a bar chart
        fig, ax = plt.subplots(figsize=(7, 5))
        ax.bar(categories, quantities, color='skyblue')
        ax.set_title('Inventory by Category')
        ax.set_xlabel('Category')
        ax.set_ylabel('Quantity')
        ax.set_xticklabels(categories, rotation=45, ha='right')

        fig.tight_layout()

        # Display the chart in the Tkinter window
        canvas = FigureCanvasTkAgg(fig, master=report_window)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Save the report to a file in the 'reports' folder
        if not os.path.exists('reports'):
            os.makedirs('reports')
        fig.savefig('reports/inventory_report.png')
        messagebox.showinfo("Report Saved", "Inventory report saved to 'reports/inventory_report.png'.")

    def reorder_report(self):
        """
        Generate and display a reorder report for products that need reordering.
        """
        # Fetch data for the report
        cursor.execute("""
            SELECT name, sku, quantity, reorder_point
            FROM products
            WHERE reorder_point IS NOT NULL AND quantity <= reorder_point
        """)
        data = cursor.fetchall()
        if not data:
            messagebox.showinfo("Information", "No products need reordering.")
            return

        report_window = tk.Toplevel(self.root)
        report_window.title("Reorder Report")
        report_window.geometry("600x400")

        # Display the data in a treeview
        tree = ttk.Treeview(report_window, columns=("Name", "SKU", "Quantity", "Reorder Point"), show='headings')
        for col in ("Name", "SKU", "Quantity", "Reorder Point"):
            tree.heading(col, text=col)
            tree.column(col, anchor=tk.CENTER)
        tree.pack(fill=tk.BOTH, expand=True)

        for row in data:
            tree.insert('', 'end', values=row)

        # Save the report to a CSV file in the 'reports' folder
        if not os.path.exists('reports'):
            os.makedirs('reports')
        df = pd.DataFrame(data, columns=["Name", "SKU", "Quantity", "Reorder Point"])
        df.to_csv('reports/reorder_report.csv', index=False)
        messagebox.showinfo("Report Saved", "Reorder report saved to 'reports/reorder_report.csv'.")

    def vendor_report(self):
        """
        Generate and display a vendor report.
        """
        # Fetch data for the report
        cursor.execute("""
            SELECT v.name, COUNT(po.id), SUM(po.total_price)
            FROM purchase_orders po
            LEFT JOIN vendors v ON po.vendor_id = v.id
            GROUP BY v.name
        """)
        data = cursor.fetchall()
        if not data:
            messagebox.showinfo("Information", "No vendor data available.")
            return

        report_window = tk.Toplevel(self.root)
        report_window.title("Vendor Report")
        report_window.geometry("600x400")

        # Display the data in a treeview
        tree = ttk.Treeview(report_window, columns=("Vendor", "Total Orders", "Total Spent"), show='headings')
        for col in ("Vendor", "Total Orders", "Total Spent"):
            tree.heading(col, text=col)
            tree.column(col, anchor=tk.CENTER)
        tree.pack(fill=tk.BOTH, expand=True)

        for row in data:
            tree.insert('', 'end', values=row)

        # Save the report to a CSV file in the 'reports' folder
        if not os.path.exists('reports'):
            os.makedirs('reports')
        df = pd.DataFrame(data, columns=["Vendor", "Total Orders", "Total Spent"])
        df.to_csv('reports/vendor_report.csv', index=False)
        messagebox.showinfo("Report Saved", "Vendor report saved to 'reports/vendor_report.csv'.")

    # =========================== User Management ===========================
    def manage_users(self):
        """
        Open the user management window.
        """
        self.user_window = tk.Toplevel(self.root)
        self.user_window.title("Manage Users")
        self.user_window.geometry("600x400")
        self.user_window.resizable(False, False)

        # User List Treeview
        columns = ("ID", "Username", "Role", "Email")
        self.user_tree = ttk.Treeview(self.user_window, columns=columns, show='headings')
        for col in columns:
            self.user_tree.heading(col, text=col)
            self.user_tree.column(col, anchor=tk.CENTER)

        scrollbar = ttk.Scrollbar(self.user_window, orient=tk.VERTICAL, command=self.user_tree.yview)
        self.user_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.user_tree.pack(fill=tk.BOTH, expand=True)
        self.user_tree.bind('<ButtonRelease-1>', self.select_user)

        # User Form
        form_frame = tk.Frame(self.user_window)
        form_frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(form_frame, text="Username").grid(row=0, column=0, pady=5)
        self.entry_user_username = tk.Entry(form_frame)
        self.entry_user_username.grid(row=0, column=1, pady=5)

        tk.Label(form_frame, text="Password").grid(row=1, column=0, pady=5)
        self.entry_user_password = tk.Entry(form_frame, show='*')
        self.entry_user_password.grid(row=1, column=1, pady=5)

        tk.Label(form_frame, text="Role").grid(row=2, column=0, pady=5)
        self.entry_user_role = ttk.Combobox(form_frame, values=['admin', 'manager', 'staff'], state='readonly')
        self.entry_user_role.grid(row=2, column=1, pady=5)

        tk.Label(form_frame, text="Email").grid(row=3, column=0, pady=5)
        self.entry_user_email = tk.Entry(form_frame)
        self.entry_user_email.grid(row=3, column=1, pady=5)

        # User Action Buttons
        btn_frame = tk.Frame(self.user_window)
        btn_frame.pack(pady=10)

        tk.Button(btn_frame, text="Add User", command=self.add_user).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Update User", command=self.update_user).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Delete User", command=self.delete_user).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Clear Fields", command=self.clear_user_fields).pack(side=tk.LEFT, padx=5)

        # Load users into the treeview
        self.load_users()

    def create_user_window(self):
        """
        Open the create new user window.
        """
        self.new_user_window = tk.Toplevel(self.root)
        self.new_user_window.title("Create New User")
        self.new_user_window.geometry("400x300")

        tk.Label(self.new_user_window, text="Create New User", font=("Arial", 14)).pack(pady=10)

        form_frame = tk.Frame(self.new_user_window)
        form_frame.pack(fill=tk.X, padx=10, pady=5)

        # Username field
        tk.Label(form_frame, text="Username").grid(row=0, column=0, pady=5)
        self.entry_new_username = tk.Entry(form_frame)
        self.entry_new_username.grid(row=0, column=1, pady=5)

        # Password field
        tk.Label(form_frame, text="Password").grid(row=1, column=0, pady=5)
        self.entry_new_password = tk.Entry(form_frame, show='*')
        self.entry_new_password.grid(row=1, column=1, pady=5)

        # Role selection
        tk.Label(form_frame, text="Role").grid(row=2, column=0, pady=5)
        self.entry_new_role = ttk.Combobox(form_frame, values=['admin', 'manager', 'staff'], state='readonly')
        self.entry_new_role.grid(row=2, column=1, pady=5)

        # Email field
        tk.Label(form_frame, text="Email").grid(row=3, column=0, pady=5)
        self.entry_new_email = tk.Entry(form_frame)
        self.entry_new_email.grid(row=3, column=1, pady=5)

        # Create user button
        tk.Button(self.new_user_window, text="Create User", command=self.create_user).pack(pady=10)

    def create_user(self):
        """
        Create a new user with password strength validation.
        """
        username = self.entry_new_username.get()
        password = self.entry_new_password.get()
        role = self.entry_new_role.get()
        email = self.entry_new_email.get()

        if username and password and role:
            if not self.validate_password_strength(password):
                return
            hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            try:
                # Insert user into the database
                cursor.execute("INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
                               (username, hashed_pw, role, email))
                conn.commit()
                messagebox.showinfo("Success", "User created successfully!")
                logging.info(f"User created: {username}")
                self.insert_audit_trail(f"Created user {username}")
                self.new_user_window.destroy()
                self.load_users()
            except sqlite3.IntegrityError:
                messagebox.showerror("Error", "Username must be unique.")
                logging.error(f"Failed to create user with duplicate username: {username}")
        else:
            messagebox.showerror("Error", "Please fill in all required fields.")

    def load_users(self):
        """
        Load users into the treeview.
        """
        if hasattr(self, 'user_tree'):
            # Clear existing users from the treeview
            for item in self.user_tree.get_children():
                self.user_tree.delete(item)
            # Fetch users from the database and insert into the treeview
            cursor.execute("SELECT id, username, role, email FROM users")
            for row in cursor.fetchall():
                self.user_tree.insert('', 'end', values=row)

    def add_user(self):
        """
        Add a new user from the manage users window with password strength validation.
        """
        username = self.entry_user_username.get()
        password = self.entry_user_password.get()
        role = self.entry_user_role.get()
        email = self.entry_user_email.get()

        if username and password and role:
            if not self.validate_password_strength(password):
                return
            hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            try:
                # Insert user into the database
                cursor.execute("INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
                               (username, hashed_pw, role, email))
                conn.commit()
                messagebox.showinfo("Success", "User added successfully!")
                logging.info(f"User added: {username}")
                self.insert_audit_trail(f"Added user {username}")
                self.load_users()
                self.clear_user_fields()
            except sqlite3.IntegrityError:
                messagebox.showerror("Error", "Username must be unique.")
                logging.error(f"Failed to add user with duplicate username: {username}")
        else:
            messagebox.showerror("Error", "Please fill in all required fields.")

    def update_user(self):
        """
        Update the selected user's details.
        """
        selected = self.user_tree.focus()
        if selected:
            user_id = self.user_tree.item(selected)['values'][0]
            username = self.entry_user_username.get()
            password = self.entry_user_password.get()
            role = self.entry_user_role.get()
            email = self.entry_user_email.get()

            if username and role:
                try:
                    if password:
                        if not self.validate_password_strength(password):
                            return
                        # Hash the new password
                        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                        # Update user in the database
                        cursor.execute("UPDATE users SET username = ?, password = ?, role = ?, email = ? WHERE id = ?",
                                       (username, hashed_pw, role, email, user_id))
                    else:
                        # Update user without changing the password
                        cursor.execute("UPDATE users SET username = ?, role = ?, email = ? WHERE id = ?",
                                       (username, role, email, user_id))
                    conn.commit()
                    messagebox.showinfo("Success", "User updated successfully!")
                    logging.info(f"User updated: {username} (ID: {user_id})")
                    self.insert_audit_trail(f"Updated user {username} (ID: {user_id})")
                    self.load_users()
                    self.clear_user_fields()
                except sqlite3.IntegrityError:
                    messagebox.showerror("Error", "Username must be unique.")
                    logging.error(f"Failed to update user with duplicate username: {username}")
            else:
                messagebox.showerror("Error", "Please fill in all required fields except password if you don't want to change it.")
        else:
            messagebox.showerror("Error", "Please select a user to update.")

    def delete_user(self):
        """
        Delete the selected user from the system.
        """
        selected = self.user_tree.focus()
        if selected:
            user_id = self.user_tree.item(selected)['values'][0]
            if user_id == self.current_user['id']:
                messagebox.showerror("Error", "You cannot delete the currently logged-in user.")
                return
            confirm = messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this user?")
            if confirm:
                # Delete user from the database
                cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
                conn.commit()
                messagebox.showinfo("Success", "User deleted successfully!")
                logging.info(f"User deleted (ID: {user_id})")
                self.insert_audit_trail(f"Deleted user (ID: {user_id})")
                self.load_users()
                self.clear_user_fields()
        else:
            messagebox.showerror("Error", "Please select a user to delete.")

    def clear_user_fields(self):
        """
        Clear all user form fields.
        """
        self.entry_user_username.delete(0, tk.END)
        self.entry_user_password.delete(0, tk.END)
        self.entry_user_role.set('')
        self.entry_user_email.delete(0, tk.END)

    def select_user(self, event):
        """
        Select a user from the treeview and display their details.
        :param event: The event object.
        """
        selected = self.user_tree.focus()
        if selected:
            values = self.user_tree.item(selected, 'values')
            self.clear_user_fields()
            self.entry_user_username.insert(0, values[1])
            self.entry_user_role.set(values[2])
            self.entry_user_email.insert(0, values[3])

    def view_audit_trail(self):
        """
        View the audit trail of user actions.
        """
        audit_window = tk.Toplevel(self.root)
        audit_window.title("Audit Trail")
        audit_window.geometry("700x500")

        # Treeview to display audit trail
        columns = ("ID", "User", "Action", "Timestamp")
        audit_tree = ttk.Treeview(audit_window, columns=columns, show='headings')
        for col in columns:
            audit_tree.heading(col, text=col)
            audit_tree.column(col, anchor=tk.CENTER)

        scrollbar = ttk.Scrollbar(audit_window, orient=tk.VERTICAL, command=audit_tree.yview)
        audit_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        audit_tree.pack(fill=tk.BOTH, expand=True)

        # Fetch audit trail data and insert into the treeview
        cursor.execute("""
            SELECT a.id, u.username, a.action, a.timestamp
            FROM audit_trail a
            LEFT JOIN users u ON a.user_id = u.id
        """)
        for row in cursor.fetchall():
            audit_tree.insert('', 'end', values=row)

    def insert_audit_trail(self, action):
        """
        Insert a new entry into the audit trail.
        :param action: Description of the action performed.
        """
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            INSERT INTO audit_trail (user_id, action, timestamp)
            VALUES (?, ?, ?)
        """, (self.current_user['id'], action, timestamp))
        conn.commit()

    # =========================== Data Import/Export ===========================
    def import_data(self):
        """
        Import data from a CSV file into the database.
        """
        filetypes = [("CSV Files", "*.csv")]
        file_path = filedialog.askopenfilename(title="Import Data", filetypes=filetypes)
        if file_path:
            try:
                df = pd.read_csv(file_path)
                table = filedialog.askstring("Table Name", "Enter the table name to import data into:")
                if table in ['products', 'vendors']:
                    df.to_sql(table, conn, if_exists='append', index=False)
                    messagebox.showinfo("Success", f"Data imported into {table} successfully!")
                    logging.info(f"Data imported into {table} from {file_path}")
                    self.refresh_all()
                else:
                    messagebox.showerror("Error", "Invalid table name.")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {e}")

    def export_data(self):
        """
        Export data from the database to a CSV file in organized folders.
        """
        table = filedialog.askstring("Table Name", "Enter the table name to export data from:")
        if table in ['products', 'vendors', 'purchase_orders']:
            if not os.path.exists('exports'):
                os.makedirs('exports')
            file_path = filedialog.asksaveasfilename(initialdir='exports/', defaultextension=".csv")
            if file_path:
                try:
                    cursor.execute(f"SELECT * FROM {table}")
                    data = cursor.fetchall()
                    columns = [desc[0] for desc in cursor.description]
                    df = pd.DataFrame(data, columns=columns)
                    df.to_csv(file_path, index=False)
                    messagebox.showinfo("Success", f"Data from {table} exported successfully!")
                    logging.info(f"Data from {table} exported to {file_path}")
                except Exception as e:
                    messagebox.showerror("Error", f"An error occurred: {e}")
        else:
            messagebox.showerror("Error", "Invalid table name.")

    # =========================== Other Methods ===========================
    def logout(self):
        """
        Logout the current user and return to the login window.
        """
        logging.info(f"User {self.current_user['username']} logged out.")
        self.insert_audit_trail('Logout')
        self.current_user = None
        self.login_window()

    def clear_window(self):
        """
        Clear all widgets from the root window.
        """
        for widget in self.root.winfo_children():
            widget.destroy()

    def refresh_all(self):
        """
        Refresh all tabs by reloading data.
        """
        self.load_products()
        self.load_vendors()
        self.load_purchase_orders()

    def get_products(self):
        """
        Get a list of product names for dropdown selections.
        :return: List of product names.
        """
        cursor.execute("SELECT name FROM products")
        products = [row[0] for row in cursor.fetchall()]
        return products

    def get_vendors(self):
        """
        Get a list of vendor names for dropdown selections.
        :return: List of vendor names.
        """
        cursor.execute("SELECT name FROM vendors")
        vendors = [row[0] for row in cursor.fetchall()]
        return vendors

    def validate_password_strength(self, password):
        """
        Validate the strength of the password.
        :param password: The password to validate.
        :return: True if the password is strong, False otherwise.
        """
        # Password must be at least 8 characters long, contain uppercase, lowercase, digit, and special character
        if len(password) < 8:
            messagebox.showerror("Weak Password", "Password must be at least 8 characters long.")
            return False
        if not re.search(r"[A-Z]", password):
            messagebox.showerror("Weak Password", "Password must contain at least one uppercase letter.")
            return False
        if not re.search(r"[a-z]", password):
            messagebox.showerror("Weak Password", "Password must contain at least one lowercase letter.")
            return False
        if not re.search(r"\d", password):
            messagebox.showerror("Weak Password", "Password must contain at least one digit.")
            return False
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            messagebox.showerror("Weak Password", "Password must contain at least one special character.")
            return False
        return True

    def __del__(self):
        """
        Destructor to close the database connection when the application exits.
        """
        conn.close()

if __name__ == "__main__":
    # Create the root window and start the application
    root = tk.Tk()
    app = InventoryManagementSystem(root)
    root.mainloop()
