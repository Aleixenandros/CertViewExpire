<?php
header('Content-Type: application/json; charset=utf-8');

// 1. Configurar la zona horaria (ajusta según tu ubicación)
date_default_timezone_set('Europe/Madrid'); // Cambia a tu zona horaria si es necesario

// 2. Cargar configuración
$config = include 'config.php';

// 3. Variables de configuración
$readModes   = $config['read_mode']      ?? ['directory'];
$directory   = $config['cert_directory'] ?? 'certificados/';
$domainsFile = $config['domains_file']   ?? 'domains.txt';

// 4. Preparar array para la respuesta JSON
$response = [
    'local'   => [], // Lista de certificados locales
    'remotes' => []  // Lista de certificados remotos
];

// ---------------------------------------------------------------------------
// Funciones de análisis
// ---------------------------------------------------------------------------
/**
 * Analiza un certificado local (.cer).
 *
 * @param string $certPath Ruta al archivo del certificado.
 * @param array $config Configuración con 'prox_expir'.
 * @return array [status, expiry (ISO 8601), state]
 */
function getLocalCertificateInfo($certPath, $config)
{
    $certContent = @file_get_contents($certPath);
    if ($certContent === false) {
        return ["Error al leer el certificado.", "N/A", "error"];
    }

    $cert = @openssl_x509_parse($certContent);
    if ($cert === false) {
        return ["Error al parsear el certificado.", "N/A", "error"];
    }

    $validToTimestamp = $cert['validTo_time_t'] ?? 0;
    $now = time();
    $validTo = date('c', $validToTimestamp); // Formato ISO 8601
    $daysToExpire = ($validToTimestamp - $now) / (60 * 60 * 24);

    // Umbral definido en config (por defecto 45)
    $umbral = $config['prox_expir'] ?? 45;

    if ($validToTimestamp < $now) {
        $daysSinceExpired = abs(floor($daysToExpire));
        return ["Caducado (hace {$daysSinceExpired} días)", $validTo, "expired"];
    } elseif ($daysToExpire <= $umbral) {
        $daysToExpireRounded = ceil($daysToExpire);
        return ["Próxima caducidad (en {$daysToExpireRounded} días)", $validTo, "expiring"];
    } else {
        $daysToExpireRounded = ceil($daysToExpire);
        return ["Válido (caduca en {$daysToExpireRounded} días)", $validTo, "valid"];
    }
}

/**
 * Analiza un certificado remoto (SSL a un dominio).
 *
 * @param string $domain Dominio a analizar.
 * @param array $config Configuración con 'prox_expir'.
 * @return array [status, expiry (ISO 8601), state]
 */
function getRemoteCertificateInfo($domain, $config)
{
    // Extraer host (por si viene con https://)
    $host = parse_url($domain, PHP_URL_HOST) ?: $domain;

    $context = stream_context_create(["ssl" => ["capture_peer_cert" => true]]);
    $fp = @stream_socket_client("ssl://{$host}:443", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $context);

    if (!$fp) {
        return ["No se pudo conectar a {$domain}: {$errstr} ({$errno})", "N/A", "error"];
    }

    $params = stream_context_get_params($fp);
    $cert   = $params['options']['ssl']['peer_certificate'] ?? null;
    fclose($fp);

    if (!$cert) {
        return ["Error al parsear el certificado remoto.", "N/A", "error"];
    }

    $parsed = @openssl_x509_parse($cert);
    if (!$parsed || !isset($parsed['validTo_time_t'])) {
        return ["Error al obtener la fecha de caducidad.", "N/A", "error"];
    }

    $validToTimestamp = $parsed['validTo_time_t'];
    $now = time();
    $validTo = date('c', $validToTimestamp); // Formato ISO 8601
    $daysToExpire = ($validToTimestamp - $now) / (60 * 60 * 24);

    // Umbral definido en config
    $umbral = $config['prox_expir'] ?? 45;

    if ($validToTimestamp < $now) {
        $daysSinceExpired = abs(floor($daysToExpire));
        return ["Caducado (hace {$daysSinceExpired} días)", $validTo, "expired"];
    } elseif ($daysToExpire <= $umbral) {
        $daysToExpireRounded = ceil($daysToExpire);
        return ["Próxima caducidad (en {$daysToExpireRounded} días)", $validTo, "expiring"];
    } else {
        $daysToExpireRounded = ceil($daysToExpire);
        return ["Válido (caduca en {$daysToExpireRounded} días)", $validTo, "valid"];
    }
}

// ---------------------------------------------------------------------------
// 5. Escanear certificados LOCALES si está activado 'directory'
// ---------------------------------------------------------------------------
if (in_array('directory', $readModes)) {
    if (is_dir($directory)) {
        // Escanear la carpeta base
        $rootItems = array_diff(scandir($directory), ['.', '..']);

        // .cer en la carpeta raíz
        $rootCer = array_filter($rootItems, function($f) use ($directory) {
            $fullPath = $directory . DIRECTORY_SEPARATOR . $f;
            return is_file($fullPath) && strtolower(pathinfo($fullPath, PATHINFO_EXTENSION)) === 'cer';
        });
        foreach ($rootCer as $cerFile) {
            $fullPath = $directory . DIRECTORY_SEPARATOR . $cerFile;
            list($status, $expiry, $state) = getLocalCertificateInfo($fullPath, $config);

            $response['local'][] = [
                'file'   => $cerFile,
                'status' => $status,
                'expiry' => $expiry,
                'state'  => $state
            ];
        }

        // Subcarpetas
        foreach ($rootItems as $possibleDir) {
            $subPath = $directory . DIRECTORY_SEPARATOR . $possibleDir;
            if (!is_dir($subPath)) {
                continue;
            }

            $subItems = array_diff(scandir($subPath), ['.', '..']);
            $cerInSub = array_filter($subItems, function($f) use ($subPath) {
                $fp = $subPath . DIRECTORY_SEPARATOR . $f;
                return is_file($fp) && strtolower(pathinfo($fp, PATHINFO_EXTENSION)) === 'cer';
            });

            foreach ($cerInSub as $cerFile) {
                $fullPath = $subPath . DIRECTORY_SEPARATOR . $cerFile;
                list($status, $expiry, $state) = getLocalCertificateInfo($fullPath, $config);

                $response['local'][] = [
                    'file'   => "$possibleDir/$cerFile",
                    'status' => $status,
                    'expiry' => $expiry,
                    'state'  => $state
                ];
            }
        }
    } else {
        // Carpeta de certificados no válida
        $response['error'] = "La carpeta de certificados '{$directory}' no existe o no es válida.";
    }
}

// ---------------------------------------------------------------------------
// 6. Escanear certificados REMOTOS si está activado 'txt'
// ---------------------------------------------------------------------------
if (in_array('txt', $readModes)) {
    if (file_exists($domainsFile)) {
        $domains = file($domainsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($domains as $domain) {
            $domain = trim($domain);
            if (!$domain) {
                continue;
            }
            list($status, $expiry, $state) = getRemoteCertificateInfo($domain, $config);
            $response['remotes'][] = [
                'domain' => $domain,
                'status' => $status,
                'expiry' => $expiry,
                'state'  => $state
            ];
        }
    } else {
        // Archivo de dominios no válido
        $response['error'] = "El archivo de dominios '{$domainsFile}' no existe o no es válido.";
    }
}

// ---------------------------------------------------------------------------
// 7. Devolver la respuesta como JSON, SIN escapar caracteres Unicode ni barras
// ---------------------------------------------------------------------------
echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
