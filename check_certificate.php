<?php
// Habilitar la visualización de errores para depuración (puedes comentar estas líneas en producción)
ini_set('display_errors', 1);
error_reporting(E_ALL);

header('Content-Type: application/json; charset=utf-8');

// Cargar la configuración (por ejemplo, para obtener 'prox_expir')
$config = include 'config.php';

// Leer JSON de la petición y obtener la URL, aplicando trim() para eliminar espacios en blanco
$input = json_decode(file_get_contents('php://input'), true);
$url = isset($input['url']) ? trim($input['url']) : null;
if (!$url) {
    echo json_encode(['error' => 'No se recibió una URL.']);
    exit;
}

/**
 * Función para obtener y analizar el certificado remoto.
 * Utiliza un contexto SSL básico (igual al usado en domains.txt)
 * y extrae la clave pública usando openssl_pkey_get_details().
 *
 * @param string $domain Dominio a analizar.
 * @param array $config Configuración (contiene 'prox_expir').
 * @return array Resultado con el estado, fecha de caducidad, certificado y clave pública, o mensaje de error.
 */
function checkRemoteCert($domain, $config) {
    // Extraer el host: si la URL incluye "https://", se obtiene el host; de lo contrario, se usa la cadena directamente
    $host = parse_url($domain, PHP_URL_HOST) ?: $domain;

    // Crear el contexto SSL básico (solo se activa "capture_peer_cert")
    $context = stream_context_create([
        "ssl" => [
            "capture_peer_cert" => true
        ]
    ]);

    // Intentar conectarse al host mediante SSL en el puerto 443
    $fp = @stream_socket_client("ssl://{$host}:443", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $context);
    if (!$fp) {
        return ['error' => "No se pudo conectar a {$domain}: $errstr ($errno)"];
    }

    // Obtener los parámetros del contexto (donde se extrae el certificado)
    $params = stream_context_get_params($fp);
    $cert   = $params['options']['ssl']['peer_certificate'] ?? null;
    fclose($fp);

    if (!$cert) {
        return ['error' => 'No se pudo obtener el certificado remoto.'];
    }

    // Parsear el certificado para obtener la fecha de caducidad
    $parsed = @openssl_x509_parse($cert);
    if (!$parsed || !isset($parsed['validTo_time_t'])) {
        return ['error' => 'No se pudo obtener la fecha de caducidad del certificado.'];
    }

    $validToTimestamp = $parsed['validTo_time_t'];
    $now = time();
    $daysToExpire = ($validToTimestamp - $now) / 86400; // 86400 segundos = 1 día
    $validTo = date('d/m/Y H:i:s', $validToTimestamp);

    // Definir el umbral (por defecto 45 días)
    $umbral = isset($config['prox_expir']) ? $config['prox_expir'] : 45;
    if ($validToTimestamp < $now) {
        $status = 'Caducado';
    } elseif ($daysToExpire <= $umbral) {
        $status = 'Próxima caducidad';
    } else {
        $status = 'Válido';
    }

    // Exportar el certificado en formato PEM
    $pemCert = '';
    openssl_x509_export($cert, $pemCert);

    // Extraer la clave pública usando openssl_pkey_get_public y openssl_pkey_get_details()
    $pubKey = openssl_pkey_get_public($pemCert);
    $pubKeyDetails = '';
    if ($pubKey) {
        $details = openssl_pkey_get_details($pubKey);
        if ($details && isset($details['key'])) {
            $pubKeyDetails = $details['key'];
        }
    }

    return [
        'status'      => $status,
        'validTo'     => $validTo,
        'daysToExpire'=> round($daysToExpire),
        'certificate' => $pemCert,
        'publicKey'   => $pubKeyDetails
    ];
}

// Ejecutar la función con la URL recibida y devolver el resultado en JSON
$result = checkRemoteCert($url, $config);
echo json_encode($result);

