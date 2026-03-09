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
  $username = $_SESSION['username'];
  $query = "SELECT * FROM \"User\" WHERE username='$username'";
  $result = pg_query($conn, $query);
  $user = pg_fetch_assoc($result);
?>
<!DOCTYPE html>
<html>
<head>
    <title>User Profile</title>
    <link rel="stylesheet" type="text/css" href="style.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>User Profile</h1>
        </div>

        <div class="content">
            <?php if (isset($_SESSION['success'])) : ?>
                <div class="success-msg">
                    <p>
                        <?php 
                            echo $_SESSION['success']; 
                            unset($_SESSION['success']);
                        ?>
                    </p>
                </div>
            <?php endif ?>

            <div class="profile-info">
                <p><strong>Username:</strong> <?php echo htmlspecialchars($user['username']); ?></p>
                <p><strong>Role(s):</strong> 
                    <?php 
                    $roles = $_SESSION['roles'] ?? [];
                    if (empty($roles)) echo "No roles assigned";
                    else echo htmlspecialchars(implode(", ", array_map('ucfirst', $roles)));
                    ?>
                </p>
                <div style="margin-top: 20px;">
                    <h3 style="margin-bottom: 10px;">Your Privileges:</h3>
                    <div class="privilege-container">
                        <?php 
                        $privs = $_SESSION['privileges'] ?? [];
                        if (empty($privs)) {
                            echo "<p style='color: #7f8c8d; font-style: italic;'>No specific privileges assigned</p>";
                        } else {
                            foreach ($privs as $priv) {
                                if ($priv === 'manage_roles') {
                                    echo "<a href='roles.php' class='privilege-item' style='text-decoration: none; cursor: pointer;'>" . htmlspecialchars(ucfirst(str_replace('_', ' ', $priv))) . "</a>";
                                } else {
                                    echo "<span class='privilege-item'>" . htmlspecialchars(ucfirst(str_replace('_', ' ', $priv))) . "</span>";
                                }
                            }
                        }
                        ?>
                    </div>
                </div>
                <p style="font-size: 14px; color: #7f8c8d; margin-top: 15px;">Your account is active and secure.</p>
            </div>

            <div class="profile-actions">
                <a href="index.php" class="btn">View All Users</a>
                <a href="profile.php?logout='1'" class="btn btn-outline">Logout</a>
            </div>
        </div>
    </div>
</body>
</html>
<?php 
  pg_close($conn);
?>
