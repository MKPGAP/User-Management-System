<?php 
session_start();
include 'config.php';

$username = "";
$errors = array();

// REGISTER USER
if (isset($_POST['register'])) {
    $username = pg_escape_string($conn, $_POST['username']);
    $password = pg_escape_string($conn, $_POST['password']);

    if (empty($username)) { array_push($errors, "Username is required"); }
    if (empty($password)) { array_push($errors, "Password is required"); }

    // Check if user exists
    $user_check_query = "SELECT * FROM \"User\" WHERE username='$username' LIMIT 1";
    $result = pg_query($conn, $user_check_query);
    $user = pg_fetch_assoc($result);
  
    if ($user) {
        if ($user['username'] === $username) {
            array_push($errors, "Username already exists");
        }
    }

    // Register user if no errors
    if (count($errors) == 0) {
        $query = "INSERT INTO \"User\" (username, password) VALUES('$username', '$password') RETURNING id";
        $result = pg_query($conn, $query);
        $new_user = pg_fetch_assoc($result);
        
        // Assign default role (Cashier = 2) or selected role
        $role_id = isset($_POST['role_id']) ? intval($_POST['role_id']) : 2;
        pg_query_params($conn, "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)", [$new_user['id'], $role_id]);
        
        $_SESSION['user_id'] = $new_user['id'];
        $_SESSION['username'] = $username;
        $_SESSION['roles'] = getUserRoles($conn, $new_user['id']);
        $_SESSION['privileges'] = getUserPrivileges($conn, $new_user['id']);
        
        $_SESSION['success'] = "You are now logged in";
        header('location: profile.php');
    }
}

// ADD USER (Enhanced)
if (isset($_POST['add_user_full'])) {
    $user_privs = $_SESSION['privileges'] ?? [];
    if (!hasPrivilege($user_privs, 'insert_users')) {
        die("Unauthorized access");
    }
    
    $username = pg_escape_string($conn, $_POST['username']);
    $password = pg_escape_string($conn, $_POST['password']);
    
    if (!empty($username) && !empty($password)) {
        pg_query($conn, "BEGIN");
        $query = "INSERT INTO \"User\" (username, password) VALUES($1, $2) RETURNING id";
        $result = pg_query_params($conn, $query, [$username, $password]);
        
        if ($result) {
            $new_user = pg_fetch_assoc($result);
            $new_id = $new_user['id'];
            
            // Assign Roles
            if (isset($_POST['role_ids']) && is_array($_POST['role_ids'])) {
                foreach ($_POST['role_ids'] as $r_id) {
                    pg_query_params($conn, "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)", [$new_id, intval($r_id)]);
                }
            }
            
            // Assign Direct Privileges
            if (isset($_POST['privilege_ids']) && is_array($_POST['privilege_ids'])) {
                foreach ($_POST['privilege_ids'] as $p_id) {
                    pg_query_params($conn, "INSERT INTO user_privileges (user_id, privilege_id) VALUES ($1, $2)", [$new_id, intval($p_id)]);
                }
            }
            
            pg_query($conn, "COMMIT");
            $_SESSION['success'] = "User account created successfully";
        } else {
            pg_query($conn, "ROLLBACK");
            $_SESSION['error'] = "Failed to create user account";
        }
        header('location: index.php');
        exit();
    }
}

// DELETE USER
if (isset($_POST['delete_user'])) {
    $user_privs = $_SESSION['privileges'] ?? [];
    if (!hasPrivilege($user_privs, 'delete_users')) {
        die("Unauthorized access");
    }
    
    $id = intval($_POST['id']);
    if ($id > 0) {
        // Delete from roles and privileges first (fk safety)
        pg_query_params($conn, "DELETE FROM user_roles WHERE user_id = $1", [$id]);
        pg_query_params($conn, "DELETE FROM user_privileges WHERE user_id = $1", [$id]);
        
        $query = "DELETE FROM \"User\" WHERE id = $1";
        $result = pg_query_params($conn, $query, [$id]);
        
        if ($result) {
            $_SESSION['success'] = "User deleted successfully";
        } else {
            $_SESSION['error'] = "Failed to delete user";
        }
        header('location: index.php');
        exit();
    }
}

// UPDATE USER
if (isset($_POST['update_user'])) {
    $user_privs = $_SESSION['privileges'] ?? [];
    if (!hasPrivilege($user_privs, 'update_users')) {
        die("Unauthorized access");
    }
    
    $id = intval($_POST['id']);
    $username = pg_escape_string($conn, $_POST['username']);
    $password = pg_escape_string($conn, $_POST['password']);
    
    if ($id > 0 && !empty($username) && !empty($password)) {
        $query = "UPDATE \"User\" SET username = $1, password = $2 WHERE id = $3";
        $result = pg_query_params($conn, $query, [$username, $password, $id]);
        
        if ($result) {
            $_SESSION['success'] = "Credential updates saved";
        } else {
            $_SESSION['error'] = "Failed to update user details";
        }
        header("location: manage_roles.php?user_id=$id");
        exit();
    }
}

// LOGIN USER
if (isset($_POST['login'])) {
    $username = pg_escape_string($conn, $_POST['username']);
    $password = pg_escape_string($conn, $_POST['password']);

    if (empty($username)) {
        array_push($errors, "Username is required");
    }
    if (empty($password)) {
        array_push($errors, "Password is required");
    }

    if (count($errors) == 0) {
        $query = "SELECT * FROM \"User\" WHERE username='$username' AND password='$password'";
        $results = pg_query($conn, $query);
        if (pg_num_rows($results) == 1) {
            $user_data = pg_fetch_assoc($results);
            $_SESSION['user_id'] = $user_data['id'];
            $_SESSION['username'] = $username;
            
            // Get user roles and privileges
            $_SESSION['roles'] = getUserRoles($conn, $user_data['id']);
            $_SESSION['privileges'] = getUserPrivileges($conn, $user_data['id']);
            
            $_SESSION['success'] = "You are now logged in";
            header('location: profile.php');
        } else {
            array_push($errors, "Wrong username/password combination");
        }
    }
}
// ASSIGN ROLE
if (isset($_POST['assign_role'])) {
    $user_privs = $_SESSION['privileges'] ?? [];
    if (!hasPrivilege($user_privs, 'manage_roles')) {
        die("Unauthorized access");
    }

    $target_user_id = intval($_POST['user_id']);
    $role_id = intval($_POST['role_id']);

    if ($target_user_id > 0 && $role_id > 0) {
        $query = "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)";
        $result = pg_query_params($conn, $query, [$target_user_id, $role_id]);
        
        if ($result) {
            $_SESSION['success'] = "Role assigned successfully";
        } else {
            $_SESSION['error'] = "Failed to assign role: " . pg_last_error($conn);
        }
        header("location: manage_roles.php?user_id=$target_user_id");
        exit();
    }
}

// REMOVE ROLE
if (isset($_POST['remove_role'])) {
    $user_privs = $_SESSION['privileges'] ?? [];
    if (!hasPrivilege($user_privs, 'manage_roles')) {
        die("Unauthorized access");
    }

    $target_user_id = intval($_POST['user_id']);
    $role_name = pg_escape_string($conn, $_POST['role_name']);

    if ($target_user_id > 0 && !empty($role_name)) {
        $query = "DELETE FROM user_roles WHERE user_id = $1 AND role_id = (SELECT id FROM roles WHERE role_name = $2)";
        $result = pg_query_params($conn, $query, [$target_user_id, $role_name]);
        
        if ($result) {
            $_SESSION['success'] = "Role removed successfully";
        } else {
            $_SESSION['error'] = "Failed to remove role: " . pg_last_error($conn);
        }
        header("location: manage_roles.php?user_id=$target_user_id");
        exit();
    }
}

// ASSIGN DIRECT PRIVILEGE
if (isset($_POST['assign_direct_privilege'])) {
    $user_privs = $_SESSION['privileges'] ?? [];
    if (!hasPrivilege($user_privs, 'manage_roles')) {
        die("Unauthorized access");
    }

    $target_user_id = intval($_POST['user_id']);
    $privilege_id = intval($_POST['privilege_id']);

    if ($target_user_id > 0 && $privilege_id > 0) {
        $query = "INSERT INTO user_privileges (user_id, privilege_id) VALUES ($1, $2)";
        $result = pg_query_params($conn, $query, [$target_user_id, $privilege_id]);
        
        if ($result) {
            $_SESSION['success'] = "Individual privilege granted";
        } else {
            $_SESSION['error'] = "Failed to grant privilege";
        }
        header("location: manage_roles.php?user_id=$target_user_id");
        exit();
    }
}

// REMOVE DIRECT PRIVILEGE
if (isset($_POST['remove_direct_privilege'])) {
    $user_privs = $_SESSION['privileges'] ?? [];
    if (!hasPrivilege($user_privs, 'manage_roles')) {
        die("Unauthorized access");
    }

    $target_user_id = intval($_POST['user_id']);
    $privilege_name = pg_escape_string($conn, $_POST['privilege_name']);

    if ($target_user_id > 0 && !empty($privilege_name)) {
        $query = "DELETE FROM user_privileges WHERE user_id = $1 AND privilege_id = (SELECT id FROM privileges WHERE privilege_name = $2)";
        $result = pg_query_params($conn, $query, [$target_user_id, $privilege_name]);
        
        if ($result) {
            $_SESSION['success'] = "Individual privilege removed";
        } else {
            $_SESSION['error'] = "Failed to remove privilege";
        }
        header("location: manage_roles.php?user_id=$target_user_id");
        exit();
    }
}
?>