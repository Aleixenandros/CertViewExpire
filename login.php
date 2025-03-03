<?php
session_start();
$config = include('config.php');
require_once('auth.php');

if ($config['login_method'] === 'LDAP') {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $username = trim($_POST['username']);
        $password = $_POST['password'];

        try {
            if (ldap_authenticate($username, $password, $config['ldap'])) {
                $_SESSION['username'] = $username;
		$_SESSION['authenticated'] = true;
                header("Location: index.php");
                exit;
            } else {
                $error = "Credenciales incorrectas.";
            }
        } catch (Exception $e) {
            $error = $e->getMessage();
        }
    }
    ?>
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <title>Inicio de sesión LDAP</title>
	<!-- Referencia al CSS externo -->
	<link rel="stylesheet" href="css/style.css">

    </head>
<body>
    <div class="login-container">
        <div class="login-box">
            <h2>Inicia sesión con LDAP</h2>
            <?php if (isset($error)) { echo "<p class='error'>{$error}</p>"; } ?>
            <form method="post" action="">
                <label for="username">Usuario:</label>
                <input type="text" name="username" id="username" required>
                <label for="password">Contraseña:</label>
                <input type="password" name="password" id="password" required>
                <button type="submit">Entrar</button>
            </form>
        </div>
    </div>
</body>
</html>
    <?php
} else {
    // Si el login LDAP está desactivado, asignar un usuario predeterminado
    $_SESSION['username'] = 'invitado';
    header("Location: index.php");
    exit;
}
?>
