<?php
header('Content-Type: application/json; charset=utf-8');

// Leer el cuerpo JSON
$input = json_decode(file_get_contents('php://input'), true);
$domain = $input['domain'] ?? null;

// Validar
if (!$domain) {
    echo json_encode(['error' => 'No se recibió ningún dominio.']);
    exit;
}

// Parsear URL para extraer host (en caso de que el dominio venga con https://)
$host = parse_url($domain, PHP_URL_HOST) ?: $domain;

$context = stream_context_create(["ssl" => ["capture_peer_cert" => true]]);
$fp = @stream_socket_client("ssl://{$host}:443", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $context);

if (!$fp) {
    echo json_encode(['error' => "No se pudo conectar a {$domain}: {$errstr} ({$errno})"]);
    exit;
}

$params = stream_context_get_params($fp);
$cert = $params['options']['ssl']['peer_certificate'] ?? null;
fclose($fp);

if (!$cert) {
    echo json_encode(['error' => 'No se pudo recuperar el certificado remoto.']);
    exit;
}

// Exportar el certificado a una cadena PEM
$exportedCert = '';
if (!openssl_x509_export($cert, $exportedCert)) {
    echo json_encode(['error' => 'Error al exportar el certificado remoto.']);
    exit;
}

// Devolver el contenido del certificado
echo json_encode(['certificate' => $exportedCert]);
exit;

