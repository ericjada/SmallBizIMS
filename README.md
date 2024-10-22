
# SmallBizIMS Inventory Management System (IMS)

This is a comprehensive Inventory Management System (IMS) built using Python and Tkinter for a graphical user interface. The system integrates with an SQLite database, supports user roles (admin, manager, and staff), and manages product, vendor, and purchase order data. It includes encryption for sensitive information and logging to track user actions.

## Features
- **User Authentication**: Users can log in with their credentials, and roles determine their access level (admin, manager, staff).
- **Products Management**: Add, update, delete, and search products. Each product has details like SKU, category, quantity, location, price, and barcode generation.
- **Vendors Management**: Manage vendor information including contact details and lead times.
- **Purchase Orders**: Create and receive purchase orders, linked with vendor and product information.
- **Reports**: Generate reports such as inventory by category, products needing reorder, and vendor statistics.
- **Audit Trail**: Admins can view an audit trail of user actions.
- **Data Import/Export**: Import and export product and vendor data in CSV format.

## Technologies Used
- **Tkinter**: Python's built-in GUI library used for the graphical interface.
- **SQLite**: Database for storing inventory, user, vendor, and purchase order data.
- **Bcrypt**: Used to hash user passwords.
- **Cryptography (Fernet)**: Used to encrypt and decrypt sensitive information.
- **Matplotlib**: Used for generating visual reports.
- **Pandas**: For data manipulation during CSV import/export.
- **Pillow**: Used for image manipulation (e.g., showing barcode images).
- **Barcode Library**: Generates barcodes for products.

## Setup Instructions

### Prerequisites
- Python 3.6 or higher
- Required Python Libraries:
  - `bcrypt`
  - `cryptography`
  - `pandas`
  - `matplotlib`
  - `pillow`
  - `python-barcode`
  - `sqlite3` (builtin)
  - `tkinter` (builtin)

### Install Required Libraries

To install the required libraries, run the following command:

```bash
pip install bcrypt cryptography pandas matplotlib pillow python-barcode
```

### Initial Setup
1. **Encryption Key Generation**: On the first run, an encryption key (`key.key`) will be generated in the project directory.
2. **Database Initialization**: The system will automatically create an SQLite database (`inventory_encrypted.db`) and the necessary tables if they do not already exist.
3. **Admin User Creation**: A default admin user with username `admin` and password `admin` will be created on the first run.

### How to Run
1. Clone the repository or download the code.
2. Open a terminal and navigate to the project directory.
3. Run the main Python file:

```bash
python main.py
```

This will launch the Inventory Management System's GUI.

## Usage

### Login
- The system starts with a login window.
- Use the default admin credentials for the first login: 
  - Username: `admin`
  - Password: `admin`

### Product Management
- Add new products with details such as SKU, name, quantity, location, and more.
- Products can be updated, deleted, or searched.
- Barcodes are generated automatically based on the product's SKU and displayed.

### Vendor Management
- Add and manage vendors' details like contact information, pricing, and lead times.
- Vendors can be searched and updated easily.

### Purchase Orders
- Create purchase orders by selecting a vendor and a product, and specifying the quantity.
- Mark purchase orders as received, which updates product inventory automatically.

### Reports
- Generate reports for inventory, reorder alerts, and vendor statistics.
- Visual reports are displayed using Matplotlib and can be exported as CSV files.

### User Management
- Admins can create, update, or delete users.
- Each user is assigned a role (admin, manager, staff) that controls their access level.

### Data Import/Export
- Import product or vendor data from CSV files.
- Export the current product, vendor, or purchase order data to CSV.

## Logging
- All user actions are logged in the `ims.log` file, with timestamps for auditing purposes.

## Screenshots

### Login Screen
![Login Screen](./screenshots/login.png)

### Main Window
![Main Window](./screenshots/main_window.png)

### Product Management
![Product Management](./screenshots/product_management.png)

## Security
- User passwords are securely hashed using Bcrypt.
- Sensitive data like database credentials are encrypted using the Fernet encryption algorithm.

## Troubleshooting
- **Issue**: Cannot log in with the admin account.
  - **Solution**: Ensure the database file `inventory_encrypted.db` is present and contains the admin user.
  
- **Issue**: CSV import/export errors.
  - **Solution**: Ensure that the CSV file is properly formatted with matching column names to the table you're importing/exporting from.

## Disclaimer

This project is provided "as is," without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.

By using this software, you acknowledge that you are solely responsible for ensuring the system’s security, compliance, and suitability for your intended use case. The developers are not liable for any loss, damage, or legal issues resulting from the misuse of this software.


