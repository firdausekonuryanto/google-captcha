<?php
session_start();
$config = require __DIR__ . '/config.php';

$error = '';
$success = '';

function verifyRecaptcha(string $token, string $secret): array
{
    if ($token === '') {
        return ['ok' => false, 'msg' => 'Silakan centang "I\'m not a robot" terlebih dahulu.'];
    }

    $ch = curl_init('https://www.google.com/recaptcha/api/siteverify');
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => http_build_query([
            'secret'   => $secret,
            'response' => $token,
            'remoteip' => $_SERVER['REMOTE_ADDR'] ?? '',
        ]),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 10,
    ]);
    $body = curl_exec($ch);
    $err  = curl_error($ch);
    curl_close($ch);

    if ($body === false) {
        error_log('reCAPTCHA cURL error: ' . $err);
        return ['ok' => false, 'msg' => 'Gagal menghubungi server verifikasi. Coba lagi.'];
    }

    $json = json_decode($body, true);
    if (empty($json['success'])) {
        error_log('reCAPTCHA failed: ' . implode(', ', $json['error-codes'] ?? []));
        return ['ok' => false, 'msg' => 'Verifikasi reCAPTCHA gagal, silakan ulangi.'];
    }

    return ['ok' => true, 'msg' => ''];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    $captcha = verifyRecaptcha($_POST['g-recaptcha-response'] ?? '', $config['recaptcha_secret_key']);

    if (!$captcha['ok']) {
        $error = $captcha['msg'];
    } elseif (
        hash_equals($config['admin_user'], $username) &&
        password_verify($password, $config['admin_pass_hash'])
    ) {
        session_regenerate_id(true);
        $_SESSION['user'] = $username;
        $success = 'Login berhasil! Selamat datang, ' . htmlspecialchars($username);
    } else {
        $error = 'Username atau password salah.';
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://www.google.com/recaptcha/api.js?hl=id" async defer></script>
</head>
<body class="bg-light">
<div class="container mt-5" style="max-width: 450px;">
    <div class="card shadow-sm">
        <div class="card-body p-4">
            <h3 class="mb-4 text-center">Secure Login</h3>

            <?php if ($error): ?>
                <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>
            <?php if ($success): ?>
                <div class="alert alert-success"><?= $success ?></div>
            <?php endif; ?>

            <form method="POST" action="">
                <div class="mb-3">
                    <label class="form-label">Username</label>
                    <input type="text" name="username" class="form-control"
                           value="<?= htmlspecialchars($_POST['username'] ?? '') ?>" required>
                </div>
                <div class="mb-3">
                    <label class="form-label">Password</label>
                    <input type="password" name="password" class="form-control" required>
                </div>

                <div class="mb-3 d-flex justify-content-center">
                    <div class="g-recaptcha"
                         data-sitekey="<?= htmlspecialchars($config['recaptcha_site_key']) ?>"></div>
                </div>

                <button type="submit" class="btn btn-primary w-100">Log In</button>
            </form>
        </div>
    </div>
</div>
</body>
</html>