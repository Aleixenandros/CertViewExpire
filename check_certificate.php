<?php
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);

    if (!isset($input['url']) || empty($input['url'])) {
        echo json_encode(['error' => 'La URL no está especificada.']);
        exit;
    }

    $url = $input['url'];

    // Validar formato de la URL
    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        echo json_encode(['error' => 'El formato de la URL no es válido.']);
        exit;
    }

    // Obtener la información del certificado
    $streamContext = stream_context_create(["ssl" => ["capture_peer_cert" => true, "verify_peer" => false, "verify_peer_name" => false], "socket" => ["timeout" => 10]]);
    $read = @stream_socket_client(
        "ssl://" . parse_url($url, PHP_URL_HOST) . ":443",
        $errno,
        $errstr,
        30,
        STREAM_CLIENT_CONNECT,
        $streamContext
    );

    if (!$read) {
        echo json_encode(['error' => 'No se pudo conectar al servidor: ' . $errstr]);
        exit;
    }

    $params = stream_context_get_params($read);
    $cert = $params['options']['ssl']['peer_certificate'];

    if (!$cert) {
        echo json_encode(['error' => 'No se pudo obtener el certificado.']);
        exit;
    }

    // Analizar el certificado
    $parsedCert = openssl_x509_parse($cert);

    if (!$parsedCert) {
        echo json_encode(['error' => 'No se pudo parsear el certificado.']);
        exit;
    }

    $validTo = date('d/m/Y', $parsedCert['validTo_time_t']);
    $currentTimestamp = time();
    $validToTimestamp = $parsedCert['validTo_time_t'];
    $daysToExpire = ($validToTimestamp - $currentTimestamp) / (60 * 60 * 24);

    if ($validToTimestamp < $currentTimestamp) {
        $status = 'Caducado';
    } elseif ($daysToExpire <= 45) {
        $status = 'Próxima caducidad';
    } else {
        $status = 'Válido';
    }

    // Extraer clave pública
    $publicKey = openssl_pkey_get_details(openssl_pkey_get_public($cert));

    if (!$publicKey) {
        echo json_encode(['error' => 'No se pudo obtener la clave pública.']);
        exit;
    }

    echo json_encode([
        'status' => $status,
        'validTo' => $validTo,
        'certificate' => openssl_x509_export($cert, $output) ? $output : 'No disponible',
        'publicKey' => $publicKey['key'] ?? 'No disponible'
    ]);
} else {
    echo json_encode(['error' => 'Método no permitido.']);
}
?>

