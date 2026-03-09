<?php
// Password recovery page
// Display form to enter email/username for password reset
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = $_POST['email'] ?? '';
    // TODO: Implement email lookup and send reset link
    echo '<p>If this email exists, a reset link will be sent.</p>';
}
?>
<!DOCTYPE html>
<html>

<head>
    <title>Forgot Password</title>
    <link rel="stylesheet" href="style.css">
</head>

<body>
    <div class="container">
        <div class="header">
            <h1>Forgot Password</h1>
        </div>
        <form method="post" action="forgot_password.php">
            <div class="input-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required>
            </div>
            <div class="input-group">
                <button type="submit" class="btn">Send Reset Link</button>
            </div>
            <p style="text-align:center; margin-top:10px;">
                <a href="login.php">Back to Login</a>
            </p>
        </form>
    </div>
</body>

</html>