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

  // Only admins can edit roles
  if (!in_array('admin', $user_roles) && !hasPrivilege($user_privs, 'manage_roles')) {
      die("Unauthorized access. You do not have permission to edit roles.");
  }

  if (!isset($_GET['role_id']) || empty($_GET['role_id'])) {
      $_SESSION['error'] = "No role selected for editing.";
      header('location: roles.php');
      exit();
  }

  $target_role_id = intval($_GET['role_id']);

  // Fetch role details
  $role_query = "SELECT role_name FROM roles WHERE id = $1";
  $role_result = pg_query_params($conn, $role_query, [$target_role_id]);
  
  if (pg_num_rows($role_result) == 0) {
      $_SESSION['error'] = "Role not found.";
      header('location: roles.php');
      exit();
  }
  $role_data = pg_fetch_assoc($role_result);

  // Fetch all available privileges
  $all_privs = getAvailablePrivileges($conn);

  // Fetch currently assigned privileges for this role
  $current_privs_query = "SELECT privilege_id FROM role_privileges WHERE role_id = $1";
  $current_privs_result = pg_query_params($conn, $current_privs_query, [$target_role_id]);
  $current_priv_ids = [];
  while ($row = pg_fetch_assoc($current_privs_result)) {
      $current_priv_ids[] = $row['privilege_id'];
  }

?>
<!DOCTYPE html>
<html>
<head>
    <title>Edit Role: <?php echo htmlspecialchars(ucfirst($role_data['role_name'])); ?></title>
    <link rel="stylesheet" type="text/css" href="style.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
</head>
<body>
    <div class="container container-large">
        <div class="header" style="justify-content: flex-start; gap: 12px; align-items: flex-baseline;">
            <h1>Edit Role</h1>
            <a href="roles.php" style="margin-left: auto; color: var(--text-secondary); text-decoration: none; font-size: 14px;">&larr; Back to Role Management</a>
        </div>

        <?php if (isset($_SESSION['error'])): ?>
            <div class="error-msg">
                ⚠️ <?php echo $_SESSION['error']; unset($_SESSION['error']); ?>
            </div>
        <?php endif; ?>
        
        <?php if (isset($_SESSION['success'])): ?>
            <div class="success-msg">
                ✨ <?php echo $_SESSION['success']; unset($_SESSION['success']); ?>
            </div>
        <?php endif; ?>

        <form method="POST" action="server.php">
            <input type="hidden" name="role_id" value="<?php echo $target_role_id; ?>">
            <input type="hidden" name="role_name" value="<?php echo htmlspecialchars($role_data['role_name']); ?>">

            <div class="content" style="display: grid; grid-template-columns: 350px 1fr; gap: 24px; align-items: start;">
                
                <!-- Left Column: Role Details -->
                <div style="display: flex; flex-direction: column; gap: 24px;">
                    <div class="form-card">
                        <h3>
                            <svg style="width:20px;height:20px" viewBox="0 0 24 24"><path fill="currentColor" d="M16 11C17.66 11 18.99 9.66 18.99 8C18.99 6.34 17.66 5 16 5C14.34 5 13 6.34 13 8C13 9.66 14.34 11 16 11ZM8 11C9.66 11 10.99 9.66 10.99 8C10.99 6.34 9.66 5 8 5C6.34 5 5 6.34 5 8C5 9.66 6.34 11 8 11ZM8 13C5.67 13 1 14.17 1 16.5V19H15V16.5C15 14.17 10.33 13 8 13ZM16 13C15.71 13 15.38 13.02 15.03 13.05C16.19 13.89 17 15.02 17 16.5V19H23V16.5C23 14.17 18.33 13 16 13Z" /></svg>
                            Role Details
                        </h3>
                        <div style="padding: 16px; background: #f8fafc; border-radius: 8px; border: 1px solid var(--border);">
                            <div style="font-size: 11px; color: var(--text-secondary); margin-bottom: 4px; text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px;">Target Role</div>
                            <div style="font-size: 20px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
                                <span class="role-badge <?php echo strtolower($role_data['role_name']); ?>"><?php echo htmlspecialchars(ucfirst($role_data['role_name'])); ?></span>
                            </div>
                        </div>
                    </div>

                    <div style="display: flex; flex-direction: column; gap: 12px;">
                        <button type="submit" name="update_role_privileges" class="btn btn-secondary" style="width: 100%; height: 50px; background: var(--secondary-gradient); font-size: 16px;">
                            Save Changes
                        </button>
                        <a href="roles.php" class="btn btn-outline" style="text-align: center; padding: 14px;">
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
                        </h3>
                        <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 20px;">Modify the default permissions any user with this role will inherit.</p>
                        <div class="privilege-container" style="justify-content: flex-start; gap: 10px;">
                            <?php foreach ($all_privs as $priv_row): ?>
                                <?php $is_checked = in_array($priv_row['id'], $current_priv_ids); ?>
                                <label class="privilege-item <?php echo $is_checked ? 'checked-item' : ''; ?>" style="cursor: pointer; display: flex; gap: 8px; align-items: center; background: <?php echo $is_checked ? '#eef2ff' : 'white'; ?>; border-color: <?php echo $is_checked ? '#6366f1' : 'var(--border)'; ?>;">
                                    <input type="checkbox" name="privilege_ids[]" value="<?php echo $priv_row['id']; ?>" <?php echo $is_checked ? 'checked' : ''; ?> style="width: 14px; height: 14px; cursor: pointer;">
                                    <?php echo htmlspecialchars(ucwords(str_replace('_', ' ', $priv_row['privilege_name']))); ?>
                                </label>
                            <?php endforeach; ?>
                        </div>
                    </div>
                </div>

            </div>
        </form>
    </div>
    
    <style>
        .checked-item { font-weight: 500; color: #4338ca; }
    </style>
</body>
</html>
<?php pg_close($conn); ?>
