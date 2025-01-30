<?php
header('Content-Type: application/json; charset=utf-8');

// Cargar config para obtener prox_expir
$config = include 'config.php';

// Leer JSON de la petición
$input = json_decode(file_get_contents('php://input'), true);
$url = $input['url'] ?? null;
if (!$url) {
    echo json_encode(['error' => 'No se recibió una URL.']);
    exit;
}

// --- Función local para analizar el certificado remoto ---
function checkRemoteCert($domain, $config)
{
    // Quitar "https://" si viniera y quedarnos con el host
    $host = parse_url($domain, PHP_URL_HOST) ?: $domain;

    $context = stream_context_create(["ssl" => ["capture_peer_cert" => true]]);
    $fp = @stream_socket_client("ssl://{$host}:443", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $context);

    if (!$fp) {
        return ['error' => "No se pudo conectar a $domain: $errstr ($errno)"];
    }

    $params = stream_context_get_params($fp);
    $cert   = $params['options']['ssl']['peer_certificate'] ?? null;
    fclose($fp);

    if (!$cert) {
        return ['error' => 'No se pudo obtener el certificado remoto.'];
    }

    $parsed = openssl_x509_parse($cert);
    if (!isset($parsed['validTo_time_t'])) {
        return ['error' => 'No se pudo obtener la fecha de caducidad.'];
    }

    $validToTimestamp = $parsed['validTo_time_t'];
    $now = time();
    $daysToExpire = ($validToTimestamp - $now) / (60 * 60 * 24);
    $validTo = date('d/m/Y H:i:s', $validToTimestamp);

    // Leer prox_expir
    $umbral = $config['prox_expir'] ?? 45;

    if ($validToTimestamp < $now) {
        $status = 'Caducado';
    } elseif ($daysToExpire <= $umbral) {
        $status = 'Próxima caducidad';
    } else {
        $status = 'Válido';
    }

    // Exportar el cert y la clave pública
    $pemCert = '';
    openssl_x509_export($cert, $pemCert);
    $certDetails = $pemCert;

    // Extraer la clave pública
    $pubKey = openssl_pkey_get_public($pemCert);
    $pubKeyDetails = '';
    if ($pubKey) {
        $pubKeyInfo = '';
        openssl_pkey_export($pubKey, $pubKeyInfo);
        $pubKeyDetails = $pubKeyInfo;
    }

    return [
        'status'     => $status,
        'validTo'    => $validTo,
        'certificate'=> $certDetails,
        'publicKey'  => $pubKeyDetails
    ];
}

// --- Ejecutar la función ---
$result = checkRemoteCert($url, $config);

// Devolver JSON
echo json_encode($result);

