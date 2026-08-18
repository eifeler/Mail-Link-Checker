<?php
declare(strict_types=1);

/**
 * Gibt das CSRF-Token der aktuellen Session zurück (erzeugt es bei Bedarf).
 */
function csrf_token(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Prüft ein übermitteltes Token gegen das Session-Token.
 */
function csrf_verify(?string $token): bool
{
    return isset($_SESSION['csrf_token'])
        && is_string($token)
        && $token !== ''
        && hash_equals($_SESSION['csrf_token'], $token);
}
