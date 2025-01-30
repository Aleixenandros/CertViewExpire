<?php
header('Content-Type: application/json; charset=utf-8');

// Leer el dominio desde la petición
$input = json_decode(file_get_contents('php://input'), true);
$domain = $input['domain'] ?? null;

if (!$domain) {
    echo json_encode(['error' => 'No se recibió ningún dominio.']);
    exit;
}

// Extraer host (si viene con https://)
$host = parse_url($domain, PHP_URL_HOST) ?: $domain;

// Conexión SSL para capturar el cert
$context = stream_context_create(["ssl" => ["capture_peer_cert" => true]]);
$fp = @stream_socket_client("ssl://{$host}:443", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $context);

if (!$fp) {
    echo json_encode(['error' => "No se pudo conectar a {$domain}: {$errstr} ({$errno})"]);
    exit;
}

$params = stream_context_get_params($fp);
$cert   = $params['options']['ssl']['peer_certificate'] ?? null;
fclose($fp);

if (!$cert) {
    echo json_encode(['error' => 'No se pudo recuperar el certificado remoto.']);
    exit;
}

// Exportar en PEM
$exportedCert = '';
if (!openssl_x509_export($cert, $exportedCert)) {
    echo json_encode(['error' => 'Error al exportar el certificado remoto.']);
    exit;
}

echo json_encode(['certificate' => $exportedCert]);

