<?php
    session_start();
    require_once 'db.php';

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!isset($_POST['username']) || !isset($_POST['password'])) {
            $error = "Username/password blank";
        } else {
            $s = $dbh->prepare('SELECT uid FROM user WHERE username=? AND password=?');
            $s->bind_param('ss', $_POST['username'], $_POST['password']);
            $s->execute();
            $s->bind_result($uid);

            if ($s->fetch()) {
                $_SESSION['id'] = $uid;
                header("Location: query.php");
            } else {
                $error = "Invalid username or password specified";
            }
        }
    }
?>
<!DOCTYPE html>
<html><body>
<form method="POST">
  <input type="text" name="username" placeholder="Username">
  <input type="password" name="password" placeholder="Password">
  <button type="submit">Sign in</button>
  <?php if (isset($error)) echo "<p>ERROR: ".$error."</p>"; ?>
</form>
<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.9-1/sha1.min.js"></script>
<script src="js/login.js"></script>
</body></html>
