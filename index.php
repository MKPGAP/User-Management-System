<?php 

  session_start(); 

  if (!isset($_SESSION['username'])) {
  	$_SESSION['msg'] = "You must log in first";
  	header('location: login.php');
    exit();
  }
  if (isset($_GET['logout'])) {
      require_once 'config.php';
      if (isset($_SESSION['username'])) {
          logAuthAction($conn, $_SESSION['username'], 'Logout');
      }
  	session_destroy();
  	unset($_SESSION['username']);
  	header("location: login.php");
    exit();
  }

  include 'config.php';
  
  // Refresh roles and privileges on every load to ensure they are never stale
  if (isset($_SESSION['user_id'])) {
      $_SESSION['roles'] = getUserRoles($conn, $_SESSION['user_id']);
      $_SESSION['privileges'] = getUserPrivileges($conn, $_SESSION['user_id']);
  }

  $user_roles = $_SESSION['roles'] ?? [];
  $user_privs = $_SESSION['privileges'] ?? [];

  $query = "SELECT id, username, password FROM \"User\" ORDER BY id ASC";
  $result = pg_query($conn, $query);

  if (!$result) {
      die("Query failed: " . pg_last_error($conn));
  }
?>
<!DOCTYPE html>
<html>
<head>
    <title>User Management System</title>
    <link rel="stylesheet" type="text/css" href="style.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <script>
        // Dead code removed - management moved to manage_roles.php
    </script>
</head>
<body>
    <div class="container container-large">
        <div class="header">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <h1>User Management</h1>
                    <p style="margin-top: 4px;">Welcome, <strong><?php echo htmlspecialchars($_SESSION['username']); ?></strong> 
                    <span style="margin-left: 8px;">
                        <?php 
                            $roles = $_SESSION['roles'] ?? [];
                            if (empty($roles)) {
                                echo "<span class='role-badge'>Guest</span>";
                            } else {
                                foreach ($roles as $role) {
                                    $role_class = strtolower($role);
                                    echo "<span class='role-badge $role_class'>" . htmlspecialchars(ucfirst($role)) . "</span> ";
                                }
                            }
                        ?>
                    </span>
                    </p>
                </div>
                <div style="display: flex; gap: 12px; align-items: center;">
                    <?php if (in_array('admin', $user_roles) || hasPrivilege($user_privs, 'manage_roles')): ?>
                        <a href="roles.php" class="btn btn-secondary" style="background: var(--info); padding: 10px 20px;">
                            Role Management
                        </a>
                        <a href="add_user.php" class="btn btn-secondary" style="background: var(--primary-gradient); padding: 10px 20px;">
                            <svg style="width:20px;height:20px;vertical-align:middle;margin-right:4px" viewBox="0 0 24 24"><path fill="currentColor" d="M19,13H13V19H11V13H5V11H11V5H13V11H19V13Z" /></svg>
                            Add New User
                        </a>
                    <?php endif; ?>
                    <a href="profile.php" class="btn btn-info">My Profile</a> 
                    <a href="index.php?logout='1'" class="btn btn-outline">Logout</a>
                </div>
            </div>
        </div>

        <?php if (isset($_SESSION['success'])) : ?>
            <div class="success-msg">
                ✨ <?php echo $_SESSION['success']; unset($_SESSION['success']); ?>
            </div>
        <?php endif ?>

        <?php if (isset($_SESSION['error'])) : ?>
            <div class="error-msg">
                ⚠️ <?php echo $_SESSION['error']; unset($_SESSION['error']); ?>
            </div>
        <?php endif ?>

        <div class="content">
            <?php if (hasPrivilege($user_privs, 'view_users')): ?>
                <?php if (pg_num_rows($result) > 0): ?>
                    <table class="user-table">
                        <thead>
                            <tr>
                                <th>User Info</th>
                                <?php if (in_array('admin', $user_roles)): ?>
                                    <th>Security</th>
                                <?php endif; ?>
                                <th style="text-align: center;">Access Control</th>
                                <?php if (hasPrivilege($user_privs, 'manage_roles')): ?>
                                    <th style="text-align: center;">Management</th>
                                <?php endif; ?>
                            </tr>
                        </thead>
                        <tbody>
                            <?php while ($row = pg_fetch_assoc($result)): ?>
                                <tr>
                                    <td>
                                        <div style="font-weight: 600; color: var(--text-primary);"><?php echo htmlspecialchars($row['username']); ?></div>
                                        <div style="font-size: 11px; color: var(--text-secondary);">ID: #<?php echo $row['id']; ?></div>
                                    </td>
                                    <?php if (in_array('admin', $user_roles)): ?>
                                        <td>
                                            <code style="background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-size: 13px;"><?php echo htmlspecialchars($row['password']); ?></code>
                                        </td>
                                    <?php endif; ?>
                                    <td style="text-align: center;">
                                        <div style="display: flex; flex-wrap: wrap; justify-content: center; gap: 6px;">
                                            <?php 
                                            $u_roles = getUserRoles($conn, $row['id']);
                                            if (empty($u_roles)) echo "<span style='font-size: 12px; color: var(--text-secondary); opacity: 0.6;'>No roles</span>";
                                            foreach ($u_roles as $r): 
                                                $r_class = strtolower($r);
                                            ?>
                                                <span class="role-badge <?php echo $r_class; ?>"><?php echo htmlspecialchars(ucfirst($r)); ?></span>
                                            <?php endforeach; ?>
                                        </div>
                                    </td>
                                    <?php if (hasPrivilege($user_privs, 'manage_roles')): ?>
                                        <td style="text-align: center;">
                                            <div style="display: flex; justify-content: center;">
                                                <a href="edit_user.php?user_id=<?php echo $row['id']; ?>" class="btn btn-small btn-secondary" style="padding: 8px 16px;">
                                                    <svg style="width:16px;height:16px;vertical-align:middle;margin-right:4px" viewBox="0 0 24 24"><path fill="currentColor" d="M12,15.5A3.5,3.5 0 0,1 8.5,12A3.5,3.5 0 0,1 12,8.5A3.5,3.5 0 0,1 15.5,12A3.5,3.5 0 0,1 12,15.5M19.43,12.97C19.47,12.65 19.5,12.33 19.5,12C19.5,11.67 19.47,11.35 19.43,11.03L21.54,9.37C21.73,9.22 21.78,8.97 21.68,8.76L19.68,5.3C19.58,5.09 19.33,5.01 19.13,5.09L16.63,6.09C16.12,5.7 15.55,5.38 14.93,5.13L14.56,2.47C14.5,2.24 14.33,2.08 14.12,2.08H10.12C9.91,2.08 9.74,2.24 9.68,2.47L9.31,5.13C8.69,5.38 8.12,5.7 7.6,6.09L5.1,5.09C4.89,5.01 4.64,5.09 4.54,5.3L2.54,8.76C2.44,8.97 2.49,9.22 2.68,9.37L4.79,11.03C4.75,11.35 4.72,11.67 4.72,12C4.72,12.33 4.75,12.65 4.79,12.97L2.68,14.63C2.49,14.78 2.44,15.03 2.54,15.24L4.54,18.7C4.64,18.91 4.89,18.99 5.1,18.91L7.6,17.91C8.11,18.3 8.68,18.62 9.30,18.87L9.67,21.53C9.72,21.76 9.89,21.92 10.10,21.92H14.10C14.31,21.92 14.48,21.76 14.54,21.53L14.91,18.87C15.53,18.62 16.10,18.3 16.61,17.91L19.11,18.91C19.32,18.99 19.57,18.91 19.67,18.7L21.67,15.24C21.77,15.03 21.72,14.78 21.53,14.63L19.43,12.97Z" /></svg>
                                                    Manage
                                                </a>
                                            </div>
                                        </td>
                                    <?php endif; ?>
                                </tr>
                            <?php endwhile; ?>
                        </tbody>
                    </table>
                <?php else: ?>
                    <div class="form-card" style="text-align: center; color: var(--text-secondary);">
                        <p>No users found in the system.</p>
                    </div>
                <?php endif; ?>
            <?php else: ?>
                <div class="error-msg" style="text-align: center;">
                    <p>Access Denied: You do not have permission to view the user registry.</p>
                </div>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>
<?php 
  pg_close($conn);
?>
