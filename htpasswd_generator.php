<?php
// EINMAL-HELFER - nach Gebrauch von diesem Server löschen!
// Erzeugt eine fertige .htpasswd-Zeile (bcrypt-Hash). Das Passwort geht
// dabei nie über das Netzwerk hinaus als an diesen Server - landet nicht
// im Chat, nicht in Git, nirgendwo sonst.
declare(strict_types=1);

$line = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = trim((string)($_POST['user'] ?? ''));
    $pass = (string)($_POST['pass'] ?? '');
    if ($user !== '' && $pass !== '' && !str_contains($user, ':')) {
        $hash = password_hash($pass, PASSWORD_BCRYPT);
        $line = "$user:$hash";
    }
}
?>
<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<title>htpasswd-Generator</title>
<style>
    body { font-family: system-ui, sans-serif; max-width: 480px; margin: 3rem auto; padding: 0 1rem; }
    input { width: 100%; padding: 0.5rem; margin: 0.25rem 0 1rem; box-sizing: border-box; }
    pre { background: #f0f0f0; padding: 1rem; overflow-x: auto; user-select: all; }
    .warn { color: #b00; font-weight: bold; }
</style>
</head>
<body>
<h2>.htpasswd-Zeile erzeugen</h2>
<p class="warn">Nach Gebrauch: diese Datei (htpasswd_generator.php) per FTP löschen!</p>

<?php if ($line): ?>
<p>Diese Zeile in <code>.htpasswd</code> eintragen (per FTP-Texteditor, eine Zeile pro Nutzer):</p>
<pre><?php echo htmlspecialchars($line); ?></pre>
<?php endif; ?>

<form method="post">
    <label>Benutzername</label>
    <input type="text" name="user" required>
    <label>Passwort</label>
    <input type="password" name="pass" required>
    <button type="submit">Hash erzeugen</button>
</form>
</body>
</html>
