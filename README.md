
# SmallBizIMS Inventory Management System (IMS)

## Overview
This Inventory Management System (IMS) is a Python-based desktop application developed using `Tkinter` for the graphical user interface (GUI). The application manages inventory, vendors, and purchase orders, along with generating reports. It includes user authentication with password hashing using `bcrypt`, account lockout mechanisms, and audit trails to track user actions.

The IMS system also features data encryption, secure password handling, and basic password strength validation. It is integrated with SQLite for managing data and includes import/export functionality for CSV files.

## Features
- **User Management**: Admins can create, update, and delete users. The system features role-based access control (admin, manager, staff).
- **Product Management**: Add, update, delete, and search products. Products are tracked with attributes like SKU, name, description, quantity, reorder point, price, barcode, expiration date, and more.
- **Vendor Management**: Manage vendors, including adding and updating vendor information (name, contact, email, address, lead time).
- **Purchase Orders**: Create purchase orders for vendors, track status (ordered/received), and automatically update inventory when purchase orders are received.
- **Reports**: Generate reports such as inventory reports, reorder reports, and vendor reports. Reports are saved in CSV format or as images.
- **Security**: Password hashing, account lockout after multiple failed login attempts, and password reset with email verification.
- **Audit Trail**: Log and track user actions like adding products, resetting passwords, etc.

## Technologies Used
- **Python**: The core programming language used to develop the application.
- **Tkinter**: For the GUI components.
- **SQLite**: For database management.
- **bcrypt**: For password hashing.
- **Fernet**: For encrypting sensitive data.
- **Pandas**: For handling CSV imports and exports.
- **Matplotlib**: For generating graphical reports.
- **Pillow (PIL)**: For image processing (e.g., barcode images).
- **Python Barcode**: For generating barcodes.

## Installation and Setup

### Prerequisites
Ensure you have Python 3.x installed. You'll also need to install the following Python libraries:
```bash
pip install bcrypt cryptography pandas matplotlib pillow python-barcode
```

### Cloning the Repository
```bash
git clone https://github.com/ericjada/SmallBizIMS
cd <repository-directory>
```

### Running the Application
To run the application, simply execute the `main.py` file:
```bash
python main.py
```

## Database Initialization
The application uses SQLite for managing data. Upon the first launch, the database (`inventory_encrypted.db`) will be automatically created along with the necessary tables. An initial admin user with the following credentials will be created:
- **Username**: `admin`
- **Password**: `Admin@123`

You can change this user’s credentials once logged in.

## Features Explained

### User Authentication and Security
- **Login**: Users must provide their username and password to log in.
- **Password Hashing**: Passwords are securely hashed using `bcrypt` before being stored in the database.
- **Account Lockout**: After five consecutive failed login attempts, an account is locked for five minutes.
- **Password Reset**: Users can reset their password by verifying their email. Passwords are validated for strength (at least 8 characters, includes uppercase, lowercase, digit, and special character).

### Product Management
Users can manage the inventory by adding, updating, deleting, and searching for products. Each product has the following attributes:
- SKU (unique identifier)
- Name
- Description
- Category
- Subcategory
- Attributes
- Quantity
- Location (warehouse, store, etc.)
- Reorder point (alert when quantity falls below this)
- Price
- Barcode (automatically generated)
- Serial numbers, Lot number, Expiration date

### Vendor Management
Vendors are managed with the following attributes:
- Name
- Contact
- Email
- Address
- Pricing info
- Lead time

### Purchase Order Management
The system allows users to create purchase orders, track their status, and update inventory when orders are received.

### Reports and Analytics
The system provides several reports:
- **Inventory Report**: Displays the current quantity of products by category.
- **Reorder Report**: Displays products that have reached their reorder points.
- **Vendor Report**: Displays vendor performance, including the total number of orders and total amount spent.

Reports can be viewed graphically or exported to CSV.

### Audit Trail
Every important action in the system (such as login, logout, adding a product, creating a user, resetting a password) is logged in an audit trail. This trail can be viewed by users with admin privileges.

## Code Structure

- **main.py**: The main file that launches the Inventory Management System.
- **key.key**: The encryption key used for encrypting sensitive data.
- **ims.log**: The log file that stores user actions and errors.
- **reports/**: Directory where generated reports (CSV and images) are saved.
- **exports/**: Directory where exported data is saved.
- **inventory_encrypted.db**: The SQLite database file.

## Screenshots

### Login Window
![Login Window](docs/screenshots/login.png)

### Main Window
![Main Window](docs/screenshots/main.png)

### Product Management
![Product Management](docs/screenshots/product_management.png)

### Reports
![Reports](docs/screenshots/reports.png)

## Security Features
- **Password Hashing**: User passwords are hashed using `bcrypt` to ensure they are not stored in plain text.
- **Account Lockout**: After five failed login attempts, the account is locked for 5 minutes to prevent brute-force attacks.
- **Password Reset**: Users must provide their email address to reset their password. The new password is subject to validation to ensure strength.

## License
This project is licensed under the MIT License. See the `LICENSE` file for more details.

## Disclaimer

This project is provided "as is," without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.

By using this software, you acknowledge that you are solely responsible for ensuring the system’s security, compliance, and suitability for your intended use case. The developers are not liable for any loss, damage, or legal issues resulting from the misuse of this software.

This project has been developed with the help of ChatGPT, an AI language model. While ChatGPT was used to assist with code generation, documentation, and design, all responsibility for the accuracy, functionality, and appropriateness of the code remains with the project maintainers.
