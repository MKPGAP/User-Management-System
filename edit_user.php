<?php 
  session_start(); 
  include 'config.php';

  if (!isset($_SESSION['username'])) {
  	$_SESSION['msg'] = "You must log in first";
  	header('location: login.php');
    exit();
  }

  // Refresh roles and privileges on every load to ensure they are never stale
  if (isset($_SESSION['user_id'])) {
      $_SESSION['roles'] = getUserRoles($conn, $_SESSION['user_id']);
      $_SESSION['privileges'] = getUserPrivileges($conn, $_SESSION['user_id']);
  }

  $user_privs = $_SESSION['privileges'] ?? [];
  $can_manage_roles = hasPrivilege($user_privs, 'manage_roles');
  $can_update = hasPrivilege($user_privs, 'update_users');
  $can_delete = hasPrivilege($user_privs, 'delete_users');

  if (!$can_manage_roles && !$can_update && !$can_delete) {
      die("Unauthorized access. You do not have permission to manage users.");
  }

  if (!isset($_GET['user_id'])) {
      header('location: index.php');
      exit();
  }

  $target_user_id = intval($_GET['user_id']);
  
  // Get target user details
  $user_query = "SELECT username FROM \"User\" WHERE id = $1";
  $user_result = pg_query_params($conn, $user_query, [$target_user_id]);
  $target_user = pg_fetch_assoc($user_result);

  if (!$target_user) {
      die("User not found.");
  }

  // Get current roles of the target user
  $current_roles = getUserRoles($conn, $target_user_id);

  // Get all available roles and their privileges
  $roles_query = "SELECT r.id, r.role_name, STRING_AGG(p.privilege_name, ', ') as privileges
                  FROM roles r
                  LEFT JOIN role_privileges rp ON r.id = rp.role_id
                  LEFT JOIN privileges p ON rp.privilege_id = p.id
                  GROUP BY r.id, r.role_name
                  ORDER BY r.id ASC";
  $roles_result = pg_query($conn, $roles_query);
  
  // Get all available privileges
  $all_privs = getAvailablePrivileges($conn);
  // Get current direct privileges for this user
  $user_direct_privs_query = "SELECT p.privilege_name FROM user_privileges up JOIN privileges p ON up.privilege_id = p.id WHERE up.user_id = $1";
  $user_direct_privs_result = pg_query_params($conn, $user_direct_privs_query, [$target_user_id]);
  $current_direct_privs = [];
  while ($row = pg_fetch_assoc($user_direct_privs_result)) {
      $current_direct_privs[] = $row['privilege_name'];
  }

  // Get user details for edit form
  $user_details_query = "SELECT username, password FROM \"User\" WHERE id = $1";
  $user_details_result = pg_query_params($conn, $user_details_query, [$target_user_id]);
  $user_details = pg_fetch_assoc($user_details_result);
?>
<!DOCTYPE html>
<html>
<head>
    <title>Manage User - <?php echo htmlspecialchars($target_user['username']); ?></title>
    <link rel="stylesheet" type="text/css" href="style.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
</head>
<body>
    <div class="container container-large">
        <div class="header" style="justify-content: flex-start; gap: 12px; align-items: flex-baseline;">
            <h1>Manage User</h1>
            <span style="color: var(--text-secondary); font-size: 14px;">Registry ID: <strong>#<?php echo $target_user_id; ?></strong></span>
            <a href="index.php" style="margin-left: auto; color: var(--text-secondary); text-decoration: none; font-size: 14px;">&larr; Back to Registry</a>
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

        <div class="content" style="display: grid; grid-template-columns: 350px 1fr; gap: 24px; align-items: start;">
            
            <!-- Left Column: Basic Info & Danger Zone -->
            <div style="display: flex; flex-direction: column; gap: 24px;">
                <!-- Account Info Form -->
                <?php if ($can_update): ?>
                <div class="form-card">
                    <h3>
                        <svg style="width:20px;height:20px" viewBox="0 0 24 24"><path fill="currentColor" d="M12,4A4,4 0 0,1 16,8A4,4 0 0,1 12,12A4,4 0 0,1 8,8A4,4 0 0,1 12,4M12,14C16.42,14 20,15.79 20,18V20H4V18C4,15.79 7.58,14 12,14Z" /></svg>
                        Edit Credentials
                    </h3>
                    <form method="POST" action="server.php">
                        <input type="hidden" name="id" value="<?php echo $target_user_id; ?>">
                        <div class="input-group">
                            <label>Username</label>
                            <input type="text" name="username" value="<?php echo htmlspecialchars($user_details['username']); ?>" required>
                        </div>
                        <div class="input-group">
                            <label>Password</label>
                            <input type="text" name="password" value="<?php echo htmlspecialchars($user_details['password']); ?>" required>
                        </div>
                        <button type="submit" name="update_user" class="btn btn-secondary" style="width: 100%; justify-content: center;">
                            Save Changes
                        </button>
                    </form>
                </div>
                <?php endif; ?>

                <!-- Danger Zone -->
                <?php if ($can_delete): ?>
                <div class="form-card" style="border: 1px solid #fecaca; background: #fffcfc;">
                    <h3 style="color: #991b1b;">
                        <svg style="width:20px;height:20px" viewBox="0 0 24 24"><path fill="currentColor" d="M13,14H11V10H13M13,18H11V16H13M1,21H23L12,2L1,21Z" /></svg>
                        Danger Zone
                    </h3>
                    <p style="font-size: 13px; color: #7f1d1d; margin-bottom: 16px;">Irreversible actions. Be careful.</p>
                    <form method="POST" action="server.php" onsubmit="return confirm('Permanently delete this user? This cannot be undone.');">
                        <input type="hidden" name="id" value="<?php echo $target_user_id; ?>">
                        <button type="submit" name="delete_user" class="btn btn-danger" style="width: 100%; justify-content: center; background: #991b1b;">
                            Delete Account
                        </button>
                    </form>
                </div>
                <?php endif; ?>
            </div>

            <!-- Right Column: Roles & Privileges -->
            <div style="display: flex; flex-direction: column; gap: 24px;">
                
                <!-- Roles Management -->
                <?php if ($can_manage_roles): ?>
                <div class="form-card">
                    <h3>
                        <svg style="width:20px;height:20px" viewBox="0 0 24 24"><path fill="currentColor" d="M12,15C7.58,15 4,16.79 4,19V21H20V19C20,16.79 16.42,15 12,15M8,9A4,4 0 0,0 12,13A4,4 0 0,0 16,9A4,4 0 0,0 8,9Z" /></svg>
                        Roles Management
                    </h3>
                    
                    <div style="margin-bottom: 24px;">
                        <span style="font-size: 12px; font-weight: 700; text-transform: uppercase; color: var(--text-secondary); display: block; margin-bottom: 12px;">Assigned Roles</span>
                        <?php if (empty($current_roles)): ?>
                            <p style="font-style: italic; color: var(--text-secondary); font-size: 13px;">No roles assigned.</p>
                        <?php else: ?>
                            <div style="display: flex; flex-wrap: wrap; gap: 10px;">
                                <?php foreach ($current_roles as $role): ?>
                                    <div style="display: flex; align-items: center; gap: 8px; padding: 6px 12px; background: #f1f5f9; border-radius: var(--radius); border: 1px solid var(--border);">
                                        <span class="role-badge <?php echo strtolower($role); ?>" style="box-shadow: none; font-size: 10px;">
                                            <?php echo htmlspecialchars(ucfirst($role)); ?>
                                        </span>
                                        <form method="POST" action="server.php" style="margin: 0; line-height: 0;">
                                            <input type="hidden" name="user_id" value="<?php echo $target_user_id; ?>">
                                            <input type="hidden" name="role_name" value="<?php echo $role; ?>">
                                            <button type="submit" name="remove_role" style="background: none; border: none; padding: 0; cursor: pointer; color: #ef4444; font-weight: 800; font-size: 16px;" title="Remove Role">&times;</button>
                                        </form>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        <?php endif; ?>
                    </div>

                    <div style="border-top: 1px solid var(--border); padding-top: 20px;">
                        <span style="font-size: 12px; font-weight: 700; text-transform: uppercase; color: var(--text-secondary); display: block; margin-bottom: 12px;">Available Roles</span>
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                            <?php 
                            pg_result_seek($roles_result, 0);
                            $available_any = false;
                            while ($role_row = pg_fetch_assoc($roles_result)) {
                                if (!in_array($role_row['role_name'], $current_roles)) {
                                    $available_any = true;
                                    ?>
                                    <div style="padding: 12px; border: 1px solid var(--border); border-radius: var(--radius); display: flex; flex-direction: column; justify-content: space-between;">
                                        <div style="margin-bottom: 10px;">
                                            <span style="font-weight: 700; color: var(--text-primary); display: block; margin-bottom: 2px;"><?php echo htmlspecialchars(ucfirst($role_row['role_name'])); ?></span>
                                            <span style="font-size: 10px; color: var(--text-secondary); line-height: 1.3; display: block;">
                                                <?php echo htmlspecialchars(ucwords(str_replace(['_', ','], [' ', ', '], $role_row['privileges'] ?: 'No privileges'))); ?>
                                            </span>
                                        </div>
                                        <form method="POST" action="server.php" style="margin: 0;">
                                            <input type="hidden" name="user_id" value="<?php echo $target_user_id; ?>">
                                            <input type="hidden" name="role_id" value="<?php echo $role_row['id']; ?>">
                                            <button type="submit" name="assign_role" class="btn btn-small btn-secondary" style="width: 100%; justify-content: center; height: 32px; font-size: 11px;">Add Role</button>
                                        </form>
                                    </div>
                                    <?php
                                }
                            }
                            if (!$available_any) echo "<p style='font-style: italic; color: var(--text-secondary); font-size: 13px;'>All roles assigned.</p>";
                            ?>
                        </div>
                    </div>
                </div>
                <?php endif; ?>

                <!-- Direct Individual Privileges Management -->
                <?php if ($can_manage_roles): ?>
                <div class="form-card" style="border-top: 4px solid var(--info);">
                    <h3>
                        <svg style="width:20px;height:20px" viewBox="0 0 24 24"><path fill="currentColor" d="M12,17L7,12H10V8H14V12H17L12,17M21,16.5C21,16.88 20.79,17.21 20.47,17.38L12.57,21.82C12.41,21.94 12.21,22 12,22C11.79,22 11.59,21.94 11.43,21.82L3.53,17.38C3.21,17.21 3,16.88 3,16.5V7.5C3,7.12 3.21,6.79 3.53,6.62L11.43,2.18C11.59,2.06 11.79,2 12,2C12.21,2 12.41,2.06 12.57,2.18L20.47,6.62C20.79,6.79 21,7.12 21,7.5V16.5Z" /></svg>
                        Individual Direct Privileges
                    </h3>
                    <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 20px;">Grant specific permissions directly to this user account.</p>

                    <div style="margin-bottom: 24px;">
                        <span style="font-size: 12px; font-weight: 700; text-transform: uppercase; color: var(--text-secondary); display: block; margin-bottom: 12px;">Directly Assigned</span>
                        <?php if (empty($current_direct_privs)): ?>
                            <p style="font-style: italic; color: var(--text-secondary); font-size: 13px;">No direct privileges assigned.</p>
                        <?php else: ?>
                            <div class="privilege-container" style="justify-content: flex-start; gap: 8px;">
                                <?php foreach ($current_direct_privs as $p_name): ?>
                                    <div class="privilege-item" style="padding: 6px 12px; font-size: 12px; background: white;">
                                        <?php echo htmlspecialchars(ucwords(str_replace('_', ' ', $p_name))); ?>
                                        <form method="POST" action="server.php" style="margin: 0; display: inline; margin-left: 8px;">
                                            <input type="hidden" name="user_id" value="<?php echo $target_user_id; ?>">
                                            <input type="hidden" name="privilege_name" value="<?php echo $p_name; ?>">
                                            <button type="submit" name="remove_direct_privilege" style="background: none; border: none; padding: 0; cursor: pointer; color: #ef4444; font-weight: 800; font-size: 14px;" title="Remove Privilege">&times;</button>
                                        </form>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        <?php endif; ?>
                    </div>

                    <div style="border-top: 1px solid var(--border); padding-top: 20px;">
                        <span style="font-size: 12px; font-weight: 700; text-transform: uppercase; color: var(--text-secondary); display: block; margin-bottom: 12px;">Available Permissions</span>
                        <div class="privilege-container" style="justify-content: flex-start; gap: 8px;">
                            <?php 
                            $available_priv_count = 0;
                            foreach ($all_privs as $priv_row) {
                                if (!in_array($priv_row['privilege_name'], $current_direct_privs)) {
                                    $available_priv_count++;
                                    ?>
                                    <form method="POST" action="server.php" style="margin: 0;">
                                        <input type="hidden" name="user_id" value="<?php echo $target_user_id; ?>">
                                        <input type="hidden" name="privilege_id" value="<?php echo $priv_row['id']; ?>">
                                        <button type="submit" name="assign_direct_privilege" class="privilege-item" style="cursor: pointer; border: 1px dashed var(--border); background: transparent; color: var(--text-secondary);">
                                            + <?php echo htmlspecialchars(ucwords(str_replace('_', ' ', $priv_row['privilege_name']))); ?>
                                        </button>
                                    </form>
                                    <?php
                                }
                            }
                            if ($available_priv_count == 0) echo "<p style='font-style: italic; color: var(--text-secondary); font-size: 13px;'>All permissions assigned.</p>";
                            ?>
                        </div>
                    </div>
                </div>
                <?php endif; ?>

            </div>
        </div>
    </div>
</body>
</html>
<?php pg_close($conn); ?>
