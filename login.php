<?php include('server.php') ?>
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <link rel="stylesheet" type="text/css" href="style.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Login</h1>
        </div>
        
        <form method="post" action="login.php">
            <?php include('error.php'); ?>
            <div class="input-group">
                <label>Username</label>
                <input type="text" name="username" >
            </div>
            <div class="input-group">
                <label>Password</label>
                <input type="password" name="password">
            </div>
            <div class="input-group">
                <button type="submit" class="btn" name="login">Login</button>
            </div>
                <p style="text-align:center; margin-top:10px;">
                    <a href="forgot_password.php">Forgot Password?</a>
                </p>
                <p>
                    Don't have an account? <a href="register.php">Register here</a>
                </p>

    </div>
</body>
</html>