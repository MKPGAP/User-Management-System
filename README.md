# User Management System

A PHP-based web application for managing users, roles, and privileges with Role-Based Access Control (RBAC) and full audit logging.

to run code -  php -S localhost:8000
---

## Prerequisites

Before running the app, ensure you have the following installed:

- **PHP 8.0+** with the `pgsql` extension enabled
- **PostgreSQL** (database server)
- **Apache** or any web server with `mod_php` (e.g. via XAMPP, MAMP, or a standalone Apache install)

---

## How to Run

### 1. Start PostgreSQL

Make sure your PostgreSQL service is running:

```bash
# macOS (Homebrew)
brew services start postgresql

# Linux
sudo systemctl start postgresql
```

### 2. Set Up the Database

Connect to PostgreSQL and create the database and required tables:

```sql
CREATE DATABASE lnbti_db;
\c lnbti_db

-- Users table
CREATE TABLE "User" (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password TEXT NOT NULL,
    salt TEXT NOT NULL
);

-- Roles table
CREATE TABLE roles (
    id SERIAL PRIMARY KEY,
    role_name VARCHAR(50) UNIQUE NOT NULL
);

-- Privileges table
CREATE TABLE privileges (
    id SERIAL PRIMARY KEY,
    privilege_name VARCHAR(50) UNIQUE NOT NULL
);

-- Junction tables
CREATE TABLE user_roles (
    user_id INT REFERENCES "User"(id) ON DELETE CASCADE,
    role_id INT REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE role_privileges (
    role_id INT REFERENCES roles(id) ON DELETE CASCADE,
    privilege_id INT REFERENCES privileges(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, privilege_id)
);

CREATE TABLE user_privileges (
    user_id INT REFERENCES "User"(id) ON DELETE CASCADE,
    privilege_id INT REFERENCES privileges(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, privilege_id)
);

-- Audit log tables
CREATE TABLE auth_log (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100),
    action TEXT,
    log_date DATE,
    log_time TIME
);

CREATE TABLE audit_log (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100),
    action TEXT,
    log_date DATE,
    log_time TIME
);
```

Seed initial roles and privileges:

```sql
INSERT INTO roles (role_name) VALUES ('admin'), ('manager'), ('cashier');

INSERT INTO privileges (privilege_name) VALUES
    ('view_users'),
    ('insert_users'),
    ('update_users'),
    ('delete_users'),
    ('manage_roles');

-- Assign full privileges to admin
INSERT INTO role_privileges (role_id, privilege_id)
SELECT r.id, p.id FROM roles r, privileges p WHERE r.role_name = 'admin';
```

### 3. Configure the Database Connection

Open `config.php` and update your credentials if needed:

```php
$host     = 'localhost';
$database = 'lnbti_db';
$user     = 'postgres';
$password = 'root';
```

### 4. Place Files in the Web Root

Copy (or symlink) the `user_app` folder into your web server's root:

```bash
# Example for macOS with Apache
cp -r user_app /Library/WebServer/Documents/

# Or if already in place (current setup)
# Files are at: /Users/anushkaperera/public_html/user_app/
```

### 5. Start the Web Server

```bash
# macOS — start Apache
sudo apachectl start

# Or use PHP's built-in server for quick testing
cd /Users/anushkaperera/public_html/user_app
php -S localhost:8000
```

### 6. Open in Browser

```
http://localhost/user_app/login.php
# or if using PHP built-in server:
http://localhost:8000/login.php
```

---

## Application Flow

### Authentication

1. **Register** (`register.php`) — Create a new account. Default role is **Cashier**.
2. **Login** (`login.php` → `server.php`) — Credentials are verified using salted bcrypt hashing. On success, the session stores `user_id`, `username`, `roles`, and `privileges`.
3. **Logout** — Clears the session and redirects to `login.php`. Login/logout events are recorded in `auth_log`.

### Pages & Access Control

| Page             | File              | Who Can Access                    |
| ---------------- | ----------------- | --------------------------------- |
| Home / User List | `index.php`       | Users with `view_users` privilege |
| Add User         | `add_user.php`    | Admin / users with `manage_roles` |
| Edit User        | `edit_user.php`   | Admin / users with `manage_roles` |
| My Profile       | `profile.php`     | Any logged-in user                |
| Role Management  | `roles.php`       | Admin / users with `manage_roles` |
| Create Role      | `create_role.php` | Admin / users with `manage_roles` |
| Edit Role        | `edit_role.php`   | Admin / users with `manage_roles` |
| Audit Logs       | `audit_logs.php`  | Admin only                        |

### Role-Based Access Control (RBAC)

Privileges are granted in two ways:

- **Via Role** — Each role has a set of default privileges (e.g. `manager` → `view_users`, `update_users`, `delete_users`).
- **Direct Assignment** — A privilege can be assigned directly to a specific user, independent of their role.

Effective privileges are always the **union** of role-based and direct privileges, computed on every page load.

#### Default Role Privilege Mapping

| Role                    | Privileges                                   |
| ----------------------- | -------------------------------------------- |
| **Super Admin / admin** | Full access (all privileges)                 |
| **Manager**             | `view_users`, `update_users`, `delete_users` |
| **Cashier**             | `view_users`, `insert_users`                 |

### Backend Processing (`server.php`)

All form submissions are handled here. Key operations:

| Action                  | POST key                  | Authorization check      |
| ----------------------- | ------------------------- | ------------------------ |
| Register                | `register`                | None (open)              |
| Add User                | `add_user_full`           | `manage_roles` privilege |
| Delete User             | `delete_user`             | `delete_users` privilege |
| Update User             | `update_user`             | `update_users` privilege |
| Login                   | `login`                   | None (open)              |
| Assign Role             | `assign_role`             | `manage_roles` privilege |
| Remove Role             | `remove_role`             | `manage_roles` privilege |
| Assign Direct Privilege | `assign_direct_privilege` | `manage_roles` privilege |
| Remove Direct Privilege | `remove_direct_privilege` | `manage_roles` privilege |
| Create Role             | `create_role`             | Admin or `manage_roles`  |
| Update Role Privileges  | `update_role_privileges`  | Admin or `manage_roles`  |

### Audit Logging (`audit_logs.php`)

- Every significant action (user creation, deletion, role assignment, page views, etc.) is recorded in the `audit_log` table.
- The Audit Logs page is **admin-only** and provides:
  - Filterable log table (by username, action, date range)
  - **Action Distribution** doughnut chart (powered by Chart.js)
  - **Activity Over Time** bar chart (last 14 days)
  - **CSV export** of filtered results

---

## File Structure

```
user_app/
├── config.php          # DB connection + shared helper functions
├── server.php          # All form/action handlers (backend logic)
├── login.php           # Login page
├── register.php        # Registration page
├── index.php           # Home — user list
├── profile.php         # Logged-in user profile
├── add_user.php        # Admin: add a new user
├── edit_user.php       # Admin: edit user roles & privileges
├── roles.php           # Role management hub
├── create_role.php     # Create a new role
├── edit_role.php       # Edit role privileges
├── audit_logs.php      # Audit log viewer & reports (admin only)
├── error.php           # Generic error page
└── style.css           # Global stylesheet (Inter font, dark/light tokens)
```

---

## Troubleshooting

| Problem                                  | Solution                                                               |
| ---------------------------------------- | ---------------------------------------------------------------------- |
| `Database connection failed`             | Ensure PostgreSQL is running and `config.php` credentials are correct  |
| Blank page / no output                   | Check PHP error logs; ensure `pgsql` extension is enabled in `php.ini` |
| `Unauthorized access` redirect           | Your user account lacks the required privilege for that page           |
| CSS not loading                          | Ensure `style.css` is in the same directory as the PHP files           |
| `fputcsv` deprecation warning (PHP 8.4+) | Already fixed — the escape parameter `"\\"` is passed explicitly       |
