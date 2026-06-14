<?php
session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['username']) && isset($_POST['password'])) {
        // Admin auth uses bcrypt-hashed credentials from secrets.php
        require_once '../db.php';
        require_once '../secrets.php';
        if ($_POST['username'] === ADMIN_USER && password_verify($_POST['password'], ADMIN_PASS_HASH)) {
            $_SESSION['admin'] = true;
            header("Location: /admin/authed.php");
            exit;
        }
    }
    $error = "Invalid credentials";
}
?>
<form method="POST">
  Username: <input name="username">
  Password: <input type="password" name="password">
  <button type="submit">Login</button>
  <?php if (isset($error)) echo "<p>$error</p>"; ?>
</form>
