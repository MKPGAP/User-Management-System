<?php 
  session_start(); 
  include 'config.php';

  if (!isset($_SESSION['username'])) {
  	$_SESSION['msg'] = "You must log in first";
  	header('location: login.php');
    exit();
  }

  // Refresh roles and privileges
  if (isset($_SESSION['user_id'])) {
      $_SESSION['roles'] = getUserRoles($conn, $_SESSION['user_id']);
      $_SESSION['privileges'] = getUserPrivileges($conn, $_SESSION['user_id']);
  }

  $user_roles = $_SESSION['roles'] ?? [];
  $user_privs = $_SESSION['privileges'] ?? [];

  // Only admins can create new roles
  if (!in_array('admin', $user_roles) && !hasPrivilege($user_privs, 'manage_roles')) {
      die("Unauthorized access. You do not have permission to create roles.");
  }

  $all_privs = getAvailablePrivileges($conn);
?>
<!DOCTYPE html>
<html>
<head>
    <title>Create New Role - User Management</title>
    <link rel="stylesheet" type="text/css" href="style.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
</head>
<body>
    <div class="container container-large">
        <div class="header" style="justify-content: flex-start; gap: 12px; align-items: flex-baseline;">
            <h1>Create New Role</h1>
            <a href="roles.php" style="margin-left: auto; color: var(--text-secondary); text-decoration: none; font-size: 14px;">&larr; Back to Role Management</a>
        </div>

        <?php if (isset($_SESSION['error'])): ?>
            <div class="error-msg">
                ⚠️ <?php echo $_SESSION['error']; unset($_SESSION['error']); ?>
            </div>
        <?php endif; ?>

        <form method="POST" action="server.php">
            <div class="content" style="display: grid; grid-template-columns: 350px 1fr; gap: 24px; align-items: start;">
                
                <!-- Left Column: Role Details -->
                <div style="display: flex; flex-direction: column; gap: 24px;">
                    <div class="form-card">
                        <h3>
                            <svg style="width:20px;height:20px" viewBox="0 0 24 24"><path fill="currentColor" d="M16 11C17.66 11 18.99 9.66 18.99 8C18.99 6.34 17.66 5 16 5C14.34 5 13 6.34 13 8C13 9.66 14.34 11 16 11ZM8 11C9.66 11 10.99 9.66 10.99 8C10.99 6.34 9.66 5 8 5C6.34 5 5 6.34 5 8C5 9.66 6.34 11 8 11ZM8 13C5.67 13 1 14.17 1 16.5V19H15V16.5C15 14.17 10.33 13 8 13ZM16 13C15.71 13 15.38 13.02 15.03 13.05C16.19 13.89 17 15.02 17 16.5V19H23V16.5C23 14.17 18.33 13 16 13Z" /></svg>
                            Role Details
                        </h3>
                        <div class="input-group">
                            <label>Role Name</label>
                            <input type="text" name="role_name" placeholder="E.g. supervisor, guest" required>
                            <p style="font-size: 11px; color: var(--text-secondary); margin-top: 4px;">Use lowercase and underscores for best compatibility.</p>
                        </div>
                    </div>

                    <div style="display: flex; flex-direction: column; gap: 12px;">
                        <button type="submit" name="create_role" class="btn btn-secondary" style="width: 100%; height: 50px; background: var(--secondary-gradient); font-size: 16px;">
                            Create Role
                        </button>
                        <a href="index.php" class="btn btn-outline" style="text-align: center; padding: 14px;">
                            Cancel
                        </a>
                    </div>
                </div>

                <!-- Right Column: Permissions -->
                <div style="display: flex; flex-direction: column; gap: 24px;">
                    <!-- Privileges Selection -->
                    <div class="form-card" style="border-top: 4px solid var(--info);">
                        <h3>
                            <svg style="width:20px;height:20px" viewBox="0 0 24 24"><path fill="currentColor" d="M12,17L7,12H10V8H14V12H17L12,17M21,16.5C21,16.88 20.79,17.21 20.47,17.38L12.57,21.82C12.41,21.94 12.21,22 12,22C11.79,22 11.59,21.94 11.43,21.82L3.53,17.38C3.21,17.21 3,16.88 3,16.5V7.5C3,7.12 3.21,6.79 3.53,6.62L11.43,2.18C11.59,2.06 11.79,2 12,2C12.21,2 12.41,2.06 12.57,2.18L20.47,6.62C20.79,6.79 21,7.12 21,7.5V16.5Z" /></svg>
                            Base Privileges
                            <span style="font-size: 11px; font-weight: normal; margin-left: auto; color: var(--text-secondary);">(Required)</span>
                        </h3>
                        <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 20px;">Select the default permissions any user with this role will inherit.</p>
                        <div class="privilege-container" style="justify-content: flex-start; gap: 10px;">
                            <?php foreach ($all_privs as $priv_row): ?>
                                <label class="privilege-item" style="cursor: pointer; display: flex; gap: 8px; align-items: center; background: white;">
                                    <input type="checkbox" name="privilege_ids[]" value="<?php echo $priv_row['id']; ?>" style="width: 14px; height: 14px; cursor: pointer;">
                                    <?php echo htmlspecialchars(ucwords(str_replace('_', ' ', $priv_row['privilege_name']))); ?>
                                </label>
                            <?php endforeach; ?>
                        </div>
                    </div>
                </div>

            </div>
        </form>
    </div>
</body>
</html>
<?php pg_close($conn); ?>
