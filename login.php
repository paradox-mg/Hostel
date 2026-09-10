<?php
declare(strict_types=1);

/*
 * ============================================================
 * Government Polytechnic Mau - Secure Dual Login Portal
 * File: login.php
 * ============================================================
 *
 * IMPORTANT:
 * 1. Create a MySQL database and users table.
 * 2. Replace DB credentials below.
 * 3. Store passwords using password_hash().
 * 4. Enable HTTPS in production.
 */

// ------------------------------------------------------------
// SECURITY HEADERS
// ------------------------------------------------------------
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Permissions-Policy: camera=(), microphone=(), geolocation=()");
header(
    "Content-Security-Policy: " .
    "default-src 'self'; " .
    "style-src 'self' 'unsafe-inline'; " .
    "script-src 'self' 'unsafe-inline'; " .
    "img-src 'self' data:; " .
    "font-src 'self' data:;"
);

// ------------------------------------------------------------
// SECURE SESSION
// ------------------------------------------------------------
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => !empty($_SERVER['HTTPS']),
    'httponly' => true,
    'samesite' => 'Strict'
]);

session_start();

// ------------------------------------------------------------
// DATABASE CONFIGURATION
// ------------------------------------------------------------
$dbHost = "localhost";
$dbName = "gpmau_portal";
$dbUser = "YOUR_DB_USERNAME";
$dbPass = "YOUR_DB_PASSWORD";

try {
    $pdo = new PDO(
        "mysql:host={$dbHost};dbname={$dbName};charset=utf8mb4",
        $dbUser,
        $dbPass,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false
        ]
    );
} catch (PDOException $e) {
    http_response_code(500);
    exit("Database connection error.");
}

// ------------------------------------------------------------
// CSRF TOKEN
// ------------------------------------------------------------
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$message = "";
$messageType = "";

// ------------------------------------------------------------
// LOGIN PROCESS
// ------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // CSRF validation
    $csrf = $_POST['csrf_token'] ?? '';

    if (
        !hash_equals(
            $_SESSION['csrf_token'],
            $csrf
        )
    ) {
        $message = "Invalid security token. Please refresh the page.";
        $messageType = "error";
    } else {

        $role = $_POST['role'] ?? '';
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        // Allowed roles only
        $allowedRoles = ['warden', 'principal'];

        if (!in_array($role, $allowedRoles, true)) {
            $message = "Invalid login panel.";
            $messageType = "error";
        }

        // Basic validation
        elseif ($username === '' || $password === '') {
            $message = "Please enter User ID and Password.";
            $messageType = "error";
        }

        elseif (strlen($username) > 100 || strlen($password) > 255) {
            $message = "Invalid login details.";
            $messageType = "error";
        }

        else {

            /*
             * Generic error message prevents user enumeration.
             */
            $genericError = "Invalid User ID or Password.";

            $stmt = $pdo->prepare(
                "SELECT id, username, password_hash, role, is_active
                 FROM users
                 WHERE username = :username
                 AND role = :role
                 LIMIT 1"
            );

            $stmt->execute([
                ':username' => $username,
                ':role' => $role
            ]);

            $user = $stmt->fetch();

            if (
                $user &&
                (int)$user['is_active'] === 1 &&
                password_verify($password, $user['password_hash'])
            ) {

                // Prevent session fixation
                session_regenerate_id(true);

                $_SESSION['user_id'] = (int)$user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['role'] = $user['role'];
                $_SESSION['logged_in'] = true;
                $_SESSION['login_time'] = time();

                // New CSRF token after authentication
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

                // Role-based redirect
                if ($user['role'] === 'warden') {
                    header("Location: admin/warden/dashboard.php");
                    exit;
                }

                if ($user['role'] === 'principal') {
                    header("Location: admin/principal/dashboard.php");
                    exit;
                }

            } else {
                $message = $genericError;
                $messageType = "error";
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<meta
    name="description"
    content="Government Polytechnic Mau - Official Administrative Login Portal"
>

<title>Administrative Login | Government Polytechnic Mau</title>

<style>

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

:root {
    --navy: #063970;
    --dark-navy: #04284f;
    --blue: #0b5cab;
    --light-blue: #eef6ff;
    --gold: #d49a00;
    --white: #ffffff;
    --text: #263238;
    --muted: #64748b;
    --border: #dbe3ec;
    --danger: #b42318;
}

body {
    font-family:
        Arial,
        Helvetica,
        sans-serif;
    min-height: 100vh;
    background:
        linear-gradient(
            135deg,
            #eef5fb 0%,
            #ffffff 50%,
            #edf4fa 100%
        );
    color: var(--text);
}

/* -----------------------------------------------------------
   TOP GOVERNMENT BAR
----------------------------------------------------------- */

.gov-bar {
    background: var(--dark-navy);
    color: #fff;
    padding: 8px 5%;
    font-size: 13px;
    display: flex;
    justify-content: space-between;
    gap: 15px;
}

.gov-bar span {
    opacity: .95;
}

/* -----------------------------------------------------------
   HEADER
----------------------------------------------------------- */

.header {
    background: #fff;
    border-bottom: 4px solid var(--gold);
    padding: 17px 5%;
    display: flex;
    align-items: center;
    gap: 18px;
}

.logo {
    width: 70px;
    height: 70px;
    border-radius: 50%;
    border: 3px solid var(--navy);
    display: flex;
    justify-content: center;
    align-items: center;
    color: var(--navy);
    font-size: 25px;
    font-weight: 800;
    background: #fff;
    flex-shrink: 0;
}

.header-text h1 {
    font-size: 22px;
    color: var(--navy);
    margin-bottom: 5px;
}

.header-text p {
    font-size: 13px;
    color: #52606d;
}

/* -----------------------------------------------------------
   MAIN
----------------------------------------------------------- */

.main {
    min-height: calc(100vh - 150px);
    display: flex;
    justify-content: center;
    align-items: center;
    padding: 45px 20px;
}

.login-container {
    width: min(1050px, 100%);
    background: #fff;
    border-radius: 14px;
    box-shadow:
        0 15px 45px rgba(3, 35, 70, .12);
    overflow: hidden;
    border: 1px solid #e3eaf2;
}

/* -----------------------------------------------------------
   TITLE
----------------------------------------------------------- */

.portal-title {
    text-align: center;
    padding: 30px 20px 20px;
}

.portal-title .badge {
    display: inline-block;
    background: var(--light-blue);
    color: var(--navy);
    padding: 7px 15px;
    border-radius: 30px;
    font-size: 12px;
    font-weight: bold;
    margin-bottom: 12px;
}

.portal-title h2 {
    font-size: 27px;
    color: var(--navy);
}

.portal-title p {
    color: var(--muted);
    margin-top: 7px;
    font-size: 14px;
}

/* -----------------------------------------------------------
   PANELS
----------------------------------------------------------- */

.panels {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0;
}

.panel {
    padding: 35px;
    position: relative;
}

.panel:first-child {
    border-right: 1px solid var(--border);
}

.panel-icon {
    width: 65px;
    height: 65px;
    margin: 0 auto 17px;
    border-radius: 50%;
    background: var(--light-blue);
    color: var(--navy);
    display: flex;
    justify-content: center;
    align-items: center;
    font-size: 27px;
    border: 1px solid #d7e7f8;
}

.panel h3 {
    text-align: center;
    color: var(--navy);
    font-size: 20px;
    margin-bottom: 5px;
}

.panel-subtitle {
    text-align: center;
    color: var(--muted);
    font-size: 13px;
    margin-bottom: 25px;
}

/* -----------------------------------------------------------
   FORM
----------------------------------------------------------- */

.form-group {
    margin-bottom: 17px;
}

.form-group label {
    display: block;
    margin-bottom: 7px;
    font-size: 13px;
    font-weight: 700;
    color: #334155;
}

.input-box {
    position: relative;
}

.input-box input {
    width: 100%;
    height: 48px;
    border: 1px solid #ccd6e2;
    border-radius: 7px;
    padding: 0 45px 0 14px;
    font-size: 14px;
    outline: none;
    transition: .2s;
}

.input-box input:focus {
    border-color: var(--blue);
    box-shadow:
        0 0 0 3px rgba(11, 92, 171, .10);
}

.input-icon {
    position: absolute;
    right: 14px;
    top: 50%;
    transform: translateY(-50%);
    color: #64748b;
    cursor: pointer;
    font-size: 16px;
}

/* -----------------------------------------------------------
   LOGIN BUTTON
----------------------------------------------------------- */

.login-btn {
    width: 100%;
    height: 48px;
    border: 0;
    border-radius: 7px;
    background: var(--navy);
    color: #fff;
    font-weight: 700;
    font-size: 14px;
    cursor: pointer;
    transition: .2s;
}

.login-btn:hover {
    background: #052d5a;
    transform: translateY(-1px);
}

.login-btn:active {
    transform: translateY(0);
}

/* -----------------------------------------------------------
   MESSAGE
----------------------------------------------------------- */

.message {
    width: min(850px, 90%);
    margin: 0 auto 20px;
    padding: 12px 15px;
    border-radius: 7px;
    text-align: center;
    font-size: 13px;
}

.message.error {
    background: #fff1f0;
    color: var(--danger);
    border: 1px solid #ffd5d2;
}

/* -----------------------------------------------------------
   FOOTER
----------------------------------------------------------- */

.footer {
    background: var(--dark-navy);
    color: #fff;
    text-align: center;
    padding: 17px;
    font-size: 12px;
}

.footer strong {
    color: #fff;
}

/* -----------------------------------------------------------
   MOBILE
----------------------------------------------------------- */

@media (max-width: 750px) {

    .gov-bar {
        flex-direction: column;
        text-align: center;
        gap: 4px;
    }

    .header {
        padding: 14px 20px;
    }

    .logo {
        width: 55px;
        height: 55px;
        font-size: 19px;
    }

    .header-text h1 {
        font-size: 17px;
    }

    .header-text p {
        font-size: 11px;
    }

    .main {
        padding: 25px 12px;
        align-items: flex-start;
    }

    .portal-title {
        padding: 25px 15px 15px;
    }

    .portal-title h2 {
        font-size: 22px;
    }

    .panels {
        grid-template-columns: 1fr;
    }

    .panel {
        padding: 28px 22px;
    }

    .panel:first-child {
        border-right: 0;
        border-bottom: 1px solid var(--border);
    }
}

@media (max-width: 400px) {

    .header {
        align-items: flex-start;
    }

    .header-text h1 {
        font-size: 15px;
    }

    .panel {
        padding: 25px 17px;
    }
}

</style>
</head>

<body>

<!-- GOVERNMENT BAR -->
<div class="gov-bar">
    <span>Government of Uttar Pradesh</span>
    <span>Official Administrative Portal</span>
</div>

<!-- HEADER -->
<header class="header">

    <!-- Replace this with actual GPMau logo -->
    <div class="logo">
        GP
    </div>

    <div class="header-text">
        <h1>Government Polytechnic Mau</h1>
        <p>
            Department of Technical Education, Uttar Pradesh
        </p>
    </div>

</header>

<!-- MAIN -->
<main class="main">

<div class="login-container">

    <div class="portal-title">
        <div class="badge">
            SECURE ADMINISTRATIVE PORTAL
        </div>

        <h2>Official Login Portal</h2>

        <p>
            Authorized personnel only
        </p>
    </div>

    <?php if ($message !== ""): ?>

        <div class="message <?= htmlspecialchars($messageType) ?>">
            <?= htmlspecialchars($message) ?>
        </div>

    <?php endif; ?>

    <div class="panels">

        <!-- ==================================================
             WARDEN LOGIN
        =================================================== -->

        <section class="panel">

            <div class="panel-icon">
                👨‍💼
            </div>

            <h3>Hostel Warden</h3>

            <p class="panel-subtitle">
                Hostel Administration Login
            </p>

            <form method="POST" autocomplete="off">

                <input
                    type="hidden"
                    name="csrf_token"
                    value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>"
                >

                <input
                    type="hidden"
                    name="role"
                    value="warden"
                >

                <div class="form-group">

                    <label for="warden_username">
                        Warden User ID
                    </label>

                    <div class="input-box">

                        <input
                            type="text"
                            id="warden_username"
                            name="username"
                            placeholder="Enter User ID"
                            maxlength="100"
                            autocomplete="username"
                            required
                        >

                        <span class="input-icon">
                            👤
                        </span>

                    </div>

                </div>

                <div class="form-group">

                    <label for="warden_password">
                        Password
                    </label>

                    <div class="input-box">

                        <input
                            type="password"
                            id="warden_password"
                            name="password"
                            placeholder="Enter Password"
                            maxlength="255"
                            autocomplete="current-password"
                            required
                        >

                        <span
                            class="input-icon"
                            onclick="togglePassword('warden_password', this)"
                            title="Show/Hide Password"
                        >
                            👁
                        </span>

                    </div>

                </div>

                <button
                    type="submit"
                    class="login-btn"
                >
                    Secure Warden Login
                </button>

            </form>

        </section>


        <!-- ==================================================
             PRINCIPAL LOGIN
        =================================================== -->

        <section class="panel">

            <div class="panel-icon">
                🎓
            </div>

            <h3>Principal</h3>

            <p class="panel-subtitle">
                Principal Administration Login
            </p>

            <form method="POST" autocomplete="off">

                <input
                    type="hidden"
                    name="csrf_token"
                    value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>"
                >

                <input
                    type="hidden"
                    name="role"
                    value="principal"
                >

                <div class="form-group">

                    <label for="principal_username">
                        Principal User ID
                    </label>

                    <div class="input-box">

                        <input
                            type="text"
                            id="principal_username"
                            name="username"
                            placeholder="Enter User ID"
                            maxlength="100"
                            autocomplete="username"
                            required
                        >

                        <span class="input-icon">
                            👤
                        </span>

                    </div>

                </div>

                <div class="form-group">

                    <label for="principal_password">
                        Password
                    </label>

                    <div class="input-box">

                        <input
                            type="password"
                            id="principal_password"
                            name="password"
                            placeholder="Enter Password"
                            maxlength="255"
                            autocomplete="current-password"
                            required
                        >

                        <span
                            class="input-icon"
                            onclick="togglePassword('principal_password', this)"
                            title="Show/Hide Password"
                        >
                            👁
                        </span>

                    </div>

                </div>

                <button
                    type="submit"
                    class="login-btn"
                >
                    Secure Principal Login
                </button>

            </form>

        </section>

    </div>

</div>

</main>

<!-- FOOTER -->
<footer class="footer">

    <strong>Government Polytechnic Mau</strong>
    <br>

    © <?= date('Y') ?> All Rights Reserved.
    | Authorized Access Only

</footer>


<script>

function togglePassword(id, icon) {

    const input = document.getElementById(id);

    if (input.type === "password") {
        input.type = "text";
        icon.textContent = "🙈";
    } else {
        input.type = "password";
        icon.textContent = "👁";
    }
}

</script>

</body>
</html>