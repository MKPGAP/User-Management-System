<?php 
  session_start(); 
  include 'config.php';

  if (!isset($_SESSION['username'])) {
  	$_SESSION['msg'] = "You must log in first";
  	header('location: login.php');
    exit();
  }

  $user_privs = $_SESSION['privileges'] ?? [];
  if (!hasPrivilege($user_privs, 'insert_users')) {
      die("Unauthorized access. You do not have permission to add users.");
  }

  $roles = getRolesWithPrivileges($conn);
  $all_privs = getAvailablePrivileges($conn);
?>
<!DOCTYPE html>
<html>
<head>
    <title>Add New User - User Management</title>
    <link rel="stylesheet" type="text/css" href="style.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
</head>
<body>
    <div class="container container-large">
        <div class="header" style="justify-content: flex-start; gap: 12px; align-items: flex-baseline;">
            <h1>Add New User</h1>
            <a href="index.php" style="margin-left: auto; color: var(--text-secondary); text-decoration: none; font-size: 14px;">&larr; Back to Registry</a>
        </div>

        <form method="POST" action="server.php">
            <div class="content" style="display: grid; grid-template-columns: 350px 1fr; gap: 24px; align-items: start;">
                
                <!-- Left Column: Credentials -->
                <div style="display: flex; flex-direction: column; gap: 24px;">
                    <div class="form-card">
                        <h3>
                            <svg style="width:20px;height:20px" viewBox="0 0 24 24"><path fill="currentColor" d="M12,4A4,4 0 0,1 16,8A4,4 0 0,1 12,12A4,4 0 0,1 8,8A4,4 0 0,1 12,4M12,14C16.42,14 20,15.79 20,18V20H4V18C4,15.79 7.58,14 12,14Z" /></svg>
                            Account Credentials
                        </h3>
                        <div class="input-group">
                            <label>Username</label>
                            <input type="text" name="username" placeholder="Choose a unique username" required>
                        </div>
                        <div class="input-group">
                            <label>Initial Password</label>
                            <input type="text" name="password" placeholder="Set a secure password" required>
                        </div>
                    </div>

                    <div style="display: flex; flex-direction: column; gap: 12px;">
                        <button type="submit" name="add_user_full" class="btn btn-secondary" style="width: 100%; height: 50px; background: var(--secondary-gradient); font-size: 16px;">
                            Create User Account
                        </button>
                        <a href="index.php" class="btn btn-outline" style="text-align: center; padding: 14px;">
                            Cancel
                        </a>
                    </div>
                </div>

                <!-- Right Column: Permissions -->
                <div style="display: flex; flex-direction: column; gap: 24px;">
                    <!-- Roles Selection -->
                    <div class="form-card">
                        <h3>
                            <svg style="width:20px;height:20px" viewBox="0 0 24 24"><path fill="currentColor" d="M12,15C7.58,15 4,16.79 4,19V21H20V19C20,16.79 16.42,15 12,15M8,9A4,4 0 0,0 12,13A4,4 0 0,0 16,9A4,4 0 0,0 12,5A4,4 0 0,0 8,9Z" /></svg>
                            Assign Initial Roles
                        </h3>
                        <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 12px;">
                            <?php foreach ($roles as $role_row): ?>
                                <label style="display: flex; align-items: flex-start; gap: 12px; padding: 16px; background: white; border: 1px solid var(--border); border-radius: var(--radius); cursor: pointer; transition: var(--transition);">
                                    <input type="checkbox" name="role_ids[]" value="<?php echo $role_row['id']; ?>" style="margin-top: 4px; width: 18px; height: 18px; cursor: pointer;">
                                    <div>
                                        <span style="font-weight: 700; display: block; color: var(--text-primary);"><?php echo htmlspecialchars(ucfirst($role_row['role_name'])); ?></span>
                                        <span style="font-size: 11px; color: var(--text-secondary); line-height: 1.4; display: block;">
                                            <?php echo htmlspecialchars(ucwords(str_replace(['_', ','], [' ', ', '], $role_row['privileges'] ?: 'No privileges'))); ?>
                                        </span>
                                    </div>
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
