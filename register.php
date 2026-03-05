<?php include('server.php') ?>
<!DOCTYPE html>
<html>
<head>
    <title>Registration Form</title>
    <link rel="stylesheet" type="text/css" href="style.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Welcome to Register</h1>
        </div>
        
        <form method="post" action="register.php">
            <?php include('error.php'); ?>
            <div class="input-group">
                <label>Username</label>
                <input type="text" name="username" value="<?php echo htmlspecialchars($username); ?>">
            </div>
            <div class="input-group">
                <label>Password</label>
                <input type="password" name="password">
            </div>
            <div class="input-group">
                <button type="submit" class="btn" name="register">Register</button>
            </div>
            <p>
                Already have an account? <a href="login.php">Sign in here</a>
            </p>
        </form>
    </div>
</body>
</html>