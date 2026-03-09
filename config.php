<?php
$host = 'localhost';
$database = 'lnbti_db';
$user = 'postgres';        
$password = 'root'; 

$conn = @pg_connect("host=$host dbname=$database user=$user password=$password");

if (!$conn) {
    die("Database connection failed. Please ensure PostgreSQL is running and the 'lnbti_db' database exists.");
}

// Function to get user roles
function getUserRoles($conn, $user_id) {
    $query = "SELECT r.role_name 
              FROM roles r 
              JOIN user_roles ur ON r.id = ur.role_id 
              WHERE ur.user_id = $1";
    $result = pg_query_params($conn, $query, [$user_id]);
    $roles = [];
    while ($row = pg_fetch_assoc($result)) {
        $roles[] = $row['role_name'];
    }
    return $roles;
}

// Function to get user privileges based on roles AND direct assignments
function getUserPrivileges($conn, $user_id) {
    $query = "SELECT p.privilege_name 
              FROM privileges p 
              JOIN role_privileges rp ON p.id = rp.privilege_id 
              JOIN user_roles ur ON rp.role_id = ur.role_id 
              WHERE ur.user_id = $1
              UNION
              SELECT p.privilege_name 
              FROM privileges p 
              JOIN user_privileges up ON p.id = up.privilege_id 
              WHERE up.user_id = $1";
    $result = pg_query_params($conn, $query, [$user_id]);
    $privileges = [];
    while ($row = pg_fetch_assoc($result)) {
        $privileges[] = $row['privilege_name'];
    }
    return $privileges;
}

// Function to get all available privileges
function getAvailablePrivileges($conn) {
    $query = "SELECT id, privilege_name FROM privileges ORDER BY privilege_name ASC";
    $result = pg_query($conn, $query);
    $privileges = [];
    while ($row = pg_fetch_assoc($result)) {
        $privileges[] = $row;
    }
    return $privileges;
}

// Function to get all available roles with their privileges
function getRolesWithPrivileges($conn) {
    $query = "SELECT r.id, r.role_name, STRING_AGG(p.privilege_name, ', ') as privileges
              FROM roles r
              LEFT JOIN role_privileges rp ON r.id = rp.role_id
              LEFT JOIN privileges p ON rp.privilege_id = p.id
              GROUP BY r.id, r.role_name
              ORDER BY r.id ASC";
    $result = pg_query($conn, $query);
    $roles = [];
    while ($row = pg_fetch_assoc($result)) {
        $roles[] = $row;
    }
    return $roles;
}

// Function to check if user has a specific privilege
function hasPrivilege($privileges, $privilege_name) {
    return in_array($privilege_name, $privileges);
}

// Function to log authentication actions
function logAuthAction($conn, $username, $action) {
    if (!$conn) return false;
    $query = "INSERT INTO auth_log (username, action, log_date, log_time) VALUES ($1, $2, CURRENT_DATE, CURRENT_TIME)";
    return @pg_query_params($conn, $query, [$username, $action]);
}

// Function to log audit actions (privilege usage, etc.)
function logAuditAction($conn, $username, $action) {
    if (!$conn) return false;
    $query = "INSERT INTO audit_log (username, action, log_date, log_time) VALUES ($1, $2, CURRENT_DATE, CURRENT_TIME)";
    return @pg_query_params($conn, $query, [$username, $action]);
}
?>
