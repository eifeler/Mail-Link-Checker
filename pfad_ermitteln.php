<?php
// EINMAL-HELFER - nach Gebrauch von diesem Server löschen!
// Zeigt den absoluten Server-Pfad dieses Verzeichnisses an, den du für
// AuthUserFile in der .htaccess brauchst.
declare(strict_types=1);
header('Content-Type: text/plain; charset=utf-8');
echo "Absoluter Pfad dieses Verzeichnisses:\n\n";
echo __DIR__ . "\n\n";
echo "In der .htaccess bei AuthUserFile eintragen als:\n";
echo __DIR__ . "/.htpasswd\n\n";
echo "Diese Datei (pfad_ermitteln.php) jetzt per FTP loeschen!\n";
