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

  // Security check: Only Admins can access Role Management
  if (!in_array('admin', $user_roles) && !hasPrivilege($user_privs, 'manage_roles')) {
      $_SESSION['error'] = "Unauthorized access to Role Management.";
      header('location: index.php');
      exit();
  }

  // Log view action
  logAuditAction($conn, $_SESSION['username'], "View Roles page");

  $roles = getRolesWithPrivileges($conn);
?>
<!DOCTYPE html>
<html>
<head>
    <title>Role Management System</title>
    <link rel="stylesheet" type="text/css" href="style.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
</head>
<body>
    <div class="container container-large">
        <div class="header">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <h1>Role Management</h1>
                    <p style="margin-top: 4px;">Welcome, <strong><?php echo htmlspecialchars($_SESSION['username']); ?></strong></p>
                </div>
                <div style="display: flex; gap: 12px; align-items: center;">
                    <a href="create_role.php" class="btn btn-secondary" style="background: var(--info); padding: 10px 20px;">
                        <svg style="width:20px;height:20px;vertical-align:middle;margin-right:4px" viewBox="0 0 24 24"><path fill="currentColor" d="M16 11C17.66 11 18.99 9.66 18.99 8C18.99 6.34 17.66 5 16 5C14.34 5 13 6.34 13 8C13 9.66 14.34 11 16 11ZM8 11C9.66 11 10.99 9.66 10.99 8C10.99 6.34 9.66 5 8 5C6.34 5 5 6.34 5 8C5 9.66 6.34 11 8 11ZM8 13C5.67 13 1 14.17 1 16.5V19H15V16.5C15 14.17 10.33 13 8 13ZM16 13C15.71 13 15.38 13.02 15.03 13.05C16.19 13.89 17 15.02 17 16.5V19H23V16.5C23 14.17 18.33 13 16 13Z" /></svg>
                        Create New Role
                    </a>
                    <a href="index.php" class="btn btn-secondary" style="background: var(--primary-gradient); padding: 10px 20px;">
                        User Register
                    </a>
                    <?php if (in_array('admin', $user_roles)): ?>
                        <a href="audit_logs.php" class="btn btn-secondary" style="background: #8b5cf6; padding: 10px 20px;">
                            <svg style="width:20px;height:20px;vertical-align:middle;margin-right:4px" viewBox="0 0 24 24"><path fill="currentColor" d="M14 2H6C4.89 2 4 2.9 4 4V20C4 21.11 4.89 22 6 22H18C19.11 22 20 21.11 20 20V8L14 2M16 16V13L19 13V16H16M13 16V13L16 13V16H13Z" /></svg>
                            Audit Logs
                        </a>
                    <?php endif; ?>
                    <a href="profile.php" class="btn btn-info">My Profile</a> 
                    <a href="roles.php?logout='1'" class="btn btn-outline">Logout</a>
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
            <?php if (!empty($roles)): ?>
                <table class="user-table">
                    <thead>
                        <tr>
                            <th>Role Identifier</th>
                            <th>Default Privileges</th>
                            <th style="text-align: center;">Management</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($roles as $row): ?>
                            <tr>
                                <td>
                                    <div style="display: flex; align-items: center; gap: 8px;">
                                        <span class="role-badge <?php echo strtolower($row['role_name']); ?>"><?php echo htmlspecialchars(ucfirst($row['role_name'])); ?></span>
                                    </div>
                                    <div style="font-size: 11px; color: var(--text-secondary); margin-top: 4px;">Role ID: #<?php echo $row['id']; ?></div>
                                </td>
                                <td>
                                    <div style="font-size: 13px; color: var(--text-secondary); line-height: 1.5; max-width: 400px;">
                                        <?php if (empty($row['privileges'])): ?>
                                            <i>No default privileges assigned.</i>
                                        <?php else: ?>
                                            <?php echo htmlspecialchars(ucwords(str_replace(['_', ','], [' ', ', '], $row['privileges']))); ?>
                                        <?php endif; ?>
                                    </div>
                                </td>
                                <td style="text-align: center;">
                                    <div style="display: flex; justify-content: center;">
                                        <a href="edit_role.php?role_id=<?php echo $row['id']; ?>" class="btn btn-small btn-secondary" style="padding: 8px 16px;">
                                            <svg style="width:16px;height:16px;vertical-align:middle;margin-right:4px" viewBox="0 0 24 24"><path fill="currentColor" d="M20.71,7.04C21.1,6.65 21.1,6 20.71,5.63L18.37,3.29C18,2.9 17.35,2.9 16.96,3.29L15.12,5.12L18.87,8.87M3,17.25V21H6.75L17.81,9.93L14.06,6.18L3,17.25Z" /></svg>
                                            Edit Role
                                        </a>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php else: ?>
                <div class="form-card" style="text-align: center; color: var(--text-secondary);">
                    <p>No roles found in the system.</p>
                </div>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>
<?php pg_close($conn); ?>
