<?php
session_start();

// Database connection
$conn = new mysqli("localhost", "root", "", "user_auth");
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Create users table if it doesn't exist
$conn->query("CREATE TABLE IF NOT EXISTS users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL
)");

// Message variable
$msg = "";

// Handle Signup
if (isset($_POST['signup'])) {
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];

    // Validation
    if (empty($username) || empty($email) || empty($password) || empty($confirm_password)) {
        $msg = "All signup fields are required.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $msg = "Invalid email format.";
    } elseif ($password !== $confirm_password) {
        $msg = "Passwords do not match.";
    } else {
        // Check if username/email exists
        $stmt = $conn->prepare("SELECT id FROM users WHERE username=? OR email=?");
        $stmt->bind_param("ss", $username, $email);
        $stmt->execute();
        $stmt->store_result();
        if ($stmt->num_rows > 0) {
            $msg = "Username or Email already exists.";
        } else {
            // Hash password and insert user
            $hashed = password_hash($password, PASSWORD_DEFAULT);
            $stmt2 = $conn->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
            $stmt2->bind_param("sss", $username, $email, $hashed);
            if ($stmt2->execute()) {
                $msg = "Signup successful! You can now login below.";
            } else {
                $msg = "Signup failed. Please try again.";
            }
            $stmt2->close();
        }
        $stmt->close();
    }
}

// Handle Login
if (isset($_POST['login'])) {
    $username_email = trim($_POST['username_email']);
    $password = $_POST['login_password'];

    if (empty($username_email) || empty($password)) {
        $msg = "All login fields are required.";
    } else {
        $stmt = $conn->prepare("SELECT id, username, password FROM users WHERE username=? OR email=?");
        $stmt->bind_param("ss", $username_email, $username_email);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows === 1) {
            $stmt->bind_result($id, $username, $hashed_password);
            $stmt->fetch();
            if (password_verify($password, $hashed_password)) {
                $_SESSION['user_id'] = $id;
                $_SESSION['username'] = $username;
                // Redirect to self to refresh and show logged-in view
                header("Location: ".$_SERVER['PHP_SELF']);
                exit;
            } else {
                $msg = "Incorrect username/email or password.";
            }
        } else {
            $msg = "Incorrect username/email or password.";
        }
        $stmt->close();
    }
}

// Handle Logout
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: ".$_SERVER['PHP_SELF']);
    exit;
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>All-in-One Login/Signup</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f8f9fa; }
        .container { max-width: 360px; margin: 40px auto; background: #fff; border-radius: 4px; padding: 20px; box-shadow: 0 0 10px #ddd; }
        h2 { text-align: center; }
        form { margin-bottom: 24px; }
        input[type=text], input[type=email], input[type=password] { width: 100%; padding: 8px; margin: 8px 0 12px; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #007bfc; color: #fff; border: none; border-radius: 4px; margin-bottom: 12px; cursor: pointer; }
        .msg { margin-bottom: 12px; color: #d00000; text-align: center; }
        .success { color: green; }
        .logout { margin-top: 20px; text-align: center; }
    </style>
</head>
<body>
<div class="container">
    <?php if (isset($_SESSION['user_id'])): ?>
        <h2>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?>!</h2>
        <p>You are logged in.</p>
        <div class="logout">
            <a href="?logout=1"><button>Logout</button></a>
        </div>
    <?php else: ?>
        <h2>Signup</h2>
        <?php if ($msg): ?>
            <div class="msg"><?php echo htmlspecialchars($msg); ?></div>
        <?php endif; ?>
        <form method="post" action="">
            <input type="text" name="username" placeholder="Username" required>
            <input type="email" name="email" placeholder="Email" required>
            <input type="password" name="password" placeholder="Password" required>
            <input type="password" name="confirm_password" placeholder="Confirm Password" required>
            <button type="submit" name="signup">Sign Up</button>
        </form>

        <h2>Login</h2>
        <form method="post" action="">
            <input type="text" name="username_email" placeholder="Username or Email" required>
            <input type="password" name="login_password" placeholder="Password" required>
            <button type="submit" name="login">Login</button>
        </form>
    <?php endif; ?>
</div>
</body>
</html>
