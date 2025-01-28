<?php
// 1. Cargar la configuración
$config = include 'config.php';

// 2. Obtener parámetros
$readModes   = $config['read_mode']      ?? ['directory']; // Puede ser ['directory','txt'], etc.
$directory   = $config['cert_directory'] ?? 'certificados/';
$domainsFile = $config['domains_file']   ?? 'domains.txt';

// 3. Variables para contadores globales
$total    = 0;
$valid    = 0;
$expiring = 0;
$expired  = 0;

/**
 * Analiza un certificado local (archivo .cer).
 * Devuelve [status, fechaExpiración, estadoCss].
 */
function getLocalCertificateInfo($certPath)
{
    $certContent = file_get_contents($certPath);
    if ($certContent === false) {
        return ["Error al leer el certificado.", "N/A", "error"];
    }
    $cert = openssl_x509_parse($certContent);
    if ($cert === false) {
        return ["Error al parsear el certificado.", "N/A", "error"];
    }

    $validToTimestamp = $cert['validTo_time_t'];
    $now = time();
    $validTo = date('d/m/Y', $validToTimestamp);
    $daysToExpire = ($validToTimestamp - $now) / (60 * 60 * 24);

    if ($validToTimestamp < $now) {
        $daysSinceExpired = abs(floor($daysToExpire));
        return ["Caducado (hace {$daysSinceExpired} días)", $validTo, "expired"];
    } elseif ($daysToExpire <= 45) {
        $daysToExpireRounded = ceil($daysToExpire);
        return ["Próxima caducidad (en {$daysToExpireRounded} días)", $validTo, "expiring"];
    } else {
        $daysToExpireRounded = ceil($daysToExpire);
        return ["Válido (caduca en {$daysToExpireRounded} días)", $validTo, "valid"];
    }
}

/**
 * Analiza un certificado remoto (conectando por SSL a un dominio).
 * Devuelve [status, fechaExpiración, estadoCss].
 */
function getRemoteCertificateInfo($domain)
{
    // Quitar "https://" si viniera y quedarnos con el host
    $host = parse_url($domain, PHP_URL_HOST) ?: $domain;

    $context = stream_context_create(["ssl" => ["capture_peer_cert" => true]]);
    $fp = @stream_socket_client("ssl://{$host}:443", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $context);

    if (!$fp) {
        return ["No se pudo conectar a {$domain}", "N/A", "error"];
    }

    $params = stream_context_get_params($fp);
    $cert   = $params['options']['ssl']['peer_certificate'] ?? null;
    fclose($fp);

    if (!$cert) {
        return ["Error al parsear el certificado remoto.", "N/A", "error"];
    }

    $parsed = openssl_x509_parse($cert);
    if (!isset($parsed['validTo_time_t'])) {
        return ["Error al obtener la fecha de caducidad.", "N/A", "error"];
    }

    $validToTimestamp = $parsed['validTo_time_t'];
    $now = time();
    $validTo = date('d/m/Y', $validToTimestamp);
    $daysToExpire = ($validToTimestamp - $now) / (60 * 60 * 24);

    if ($validToTimestamp < $now) {
        $daysSinceExpired = abs(floor($daysToExpire));
        return ["Caducado (hace {$daysSinceExpired} días)", $validTo, "expired"];
    } elseif ($daysToExpire <= 45) {
        $daysToExpireRounded = ceil($daysToExpire);
        return ["Próxima caducidad (en {$daysToExpireRounded} días)", $validTo, "expiring"];
    } else {
        $daysToExpireRounded = ceil($daysToExpire);
        return ["Válido (caduca en {$daysToExpireRounded} días)", $validTo, "valid"];
    }
}

// 4. Separar los certificados en dos arrays distintos
$certificateItemsLocal  = [];
$certificateItemsRemote = [];

// 4a. Si en $readModes existe 'directory', leer archivos .cer
if (in_array('directory', $readModes)) {
    if (!is_dir($directory)) {
        die("Error: la carpeta '{$directory}' no existe o no es válida.");
    }

    $files = array_diff(scandir($directory), ['.', '..']);
    $cerFiles = array_filter($files, function($file) use ($directory) {
        return pathinfo($directory . $file, PATHINFO_EXTENSION) === 'cer';
    });

    foreach ($cerFiles as $file) {
        $certificateItemsLocal[] = [
            'display' => $file,
            'source'  => $directory . DIRECTORY_SEPARATOR . $file,
        ];
    }
}

// 4b. Si en $readModes existe 'txt', leer dominios de un fichero
if (in_array('txt', $readModes)) {
    if (!file_exists($domainsFile)) {
        die("Error: el archivo de dominios '{$domainsFile}' no existe o no es válido.");
    }

    $domains = file($domainsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($domains as $domain) {
        $domain = trim($domain);
        if ($domain) {
            $certificateItemsRemote[] = [
                'display' => $domain,
                'source'  => $domain,
            ];
        }
    }
}

?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Certificados</title>
    <style>
        .container {
            width: 80%;
            margin: 0 auto;
        }
        @media (max-width: 768px) {
            .container {
                width: 100%;
            }
        }
        .summary {
            display: flex;
            justify-content: space-around;
            margin: 20px 0;
        }
        .summary-item {
            text-align: center;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            flex: 1;
            margin: 0 10px;
        }
        .summary-item.valid {
            background-color: #d4edda;
            color: #155724;
        }
        .summary-item.expiring {
            background-color: #fff3cd;
            color: #856404;
        }
        .summary-item.expired {
            background-color: #f8d7da;
            color: #721c24;
        }
        .summary-item.total {
            background-color: #e2e3e5;
            color: #383d41;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 10px;
            border: 1px solid #ddd;
            text-align: left;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .expired td {
            background-color: #f8d7da;
            color: #721c24;
        }
        .expiring-soon td {
            background-color: #fff3cd;
            color: #856404;
        }
        .valid td {
            background-color: #d4edda;
            color: #155724;
        }
        .url-check {
            margin: 20px 0;
            padding: 10px;
            border: 1px solid #ddd;
            background-color: #f9f9f9;
        }
        .url-check input[type="text"] {
            width: calc(100% - 120px);
            padding: 8px;
            margin-right: 10px;
        }
        .url-check button {
            padding: 8px 15px;
            cursor: pointer;
        }
        .url-result, .cert-details {
            margin-top: 10px;
            padding: 10px;
            border: 1px solid #ddd;
            background-color: #e9ecef;
            white-space: pre-wrap;
            display: none;
        }
        .action-buttons {
            margin-top: 10px;
        }
        .action-buttons button {
            margin-right: 10px;
        }
    </style>
</head>
<body>

<div class="container">
    <!-- Resumen de certificados -->
    <div class="summary" id="summary">
        <div class="summary-item total">
            <div id="totalCertificates">0</div>
            <div>Total Certificados</div>
        </div>
        <div class="summary-item valid">
            <div id="validCertificates">0</div>
            <div>Certificados Válidos</div>
        </div>
        <div class="summary-item expiring">
            <div id="expiringCertificates">0</div>
            <div>Próximos a Caducar</div>
        </div>
        <div class="summary-item expired">
            <div id="expiredCertificates">0</div>
            <div>Certificados Caducados</div>
        </div>
    </div>

    <!-- Comprobar URL manualmente -->
    <div class="url-check">
        <label for="urlInput">Comprobar URL:</label>
        <input type="text" id="urlInput" placeholder="https://example.com">
        <button onclick="checkCertificate()">Comprobar</button>
        <button onclick="clearResults()">Limpiar</button>
        <div id="urlResult" class="url-result"></div>
        <div class="action-buttons" id="urlActionButtons" style="display:none;">
            <button onclick="showCertificateDetails()">Mostrar Certificado</button>
            <button onclick="showPublicKeyDetails()">Mostrar Clave Pública</button>
        </div>
    </div>

    <!-- Tabla unificada -->
    <table id="certificatesTable">
        <thead>
            <tr>
                <th>Certificado / Dominio</th>
                <th>Caducidad</th>
                <th>Estado</th>
                <th>Acción</th>
            </tr>
        </thead>

        <!-- Tbody para LOCALES -->
        <tbody id="tbodyLocal">
        <?php if (!empty($certificateItemsLocal)): ?>
            <tr><th colspan="4" style="background-color:#ccc;">Certificados locales</th></tr>
            <?php
            // Listar cada .cer de la carpeta
            foreach ($certificateItemsLocal as $item) {
                list($status, $expiryDate, $state) = getLocalCertificateInfo($item['source']);

                // Actualizar contadores
                $total++;
                if ($state === "valid")    $valid++;
                if ($state === "expiring") $expiring++;
                if ($state === "expired")  $expired++;

                // Acción: mostrar contenido local
                $buttonAction = "showCertificateContent('{$item['source']}')";
                echo "<tr class=\"{$state}\">
                        <td>{$item['display']}</td>
                        <td>{$expiryDate}</td>
                        <td>{$status}</td>
                        <td><button onclick=\"{$buttonAction}\">Mostrar Certificado</button></td>
                      </tr>";
            }
            ?>
        <?php endif; ?>
        </tbody>

        <!-- Tbody para REMOTOS (dominios .txt) -->
        <tbody id="tbodyRemote">
        <?php if (!empty($certificateItemsRemote)): ?>
            <tr><th colspan="4" style="background-color:#ccc;">Certificados remotos (dominios)</th></tr>
            <?php
            // Listar cada dominio del fichero
            foreach ($certificateItemsRemote as $item) {
                list($status, $expiryDate, $state) = getRemoteCertificateInfo($item['source']);

                // Actualizar contadores
                $total++;
                if ($state === "valid")    $valid++;
                if ($state === "expiring") $expiring++;
                if ($state === "expired")  $expired++;

                // Acción: mostrar contenido remoto
                $buttonAction = "showRemoteCertificateContent('{$item['source']}')";
                echo "<tr class=\"{$state}\">
                        <td>{$item['display']}</td>
                        <td>{$expiryDate}</td>
                        <td>{$status}</td>
                        <td><button onclick=\"{$buttonAction}\">Mostrar Certificado</button></td>
                      </tr>";
            }
            ?>
        <?php endif; ?>
        </tbody>
    </table>
    <div id="certDetails" class="cert-details"></div>
</div>

<script>
    // Mostrar contadores
    document.getElementById("totalCertificates").textContent    = <?php echo $total; ?>;
    document.getElementById("validCertificates").textContent    = <?php echo $valid; ?>;
    document.getElementById("expiringCertificates").textContent = <?php echo $expiring; ?>;
    document.getElementById("expiredCertificates").textContent  = <?php echo $expired; ?>;

    let urlCertificateDetails = "";
    let urlPublicKeyDetails   = "";

    // Comprobar el certificado de una URL (check_certificate.php)
    async function checkCertificate() {
        const urlInput      = document.getElementById("urlInput").value;
        const resultDiv     = document.getElementById("urlResult");
        const actionButtons = document.getElementById("urlActionButtons");

        if (!urlInput) {
            resultDiv.style.display = "block";
            resultDiv.textContent   = "Por favor, ingrese una URL.";
            actionButtons.style.display = "none";
            return;
        }

        try {
            const response = await fetch("check_certificate.php", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ url: urlInput })
            });

            const result = await response.json();

            if (result.error) {
                resultDiv.style.display = "block";
                resultDiv.textContent   = `Error: ${result.error}`;
                actionButtons.style.display = "none";
            } else {
                resultDiv.style.display = "block";
                resultDiv.innerHTML = `Estado del certificado para <strong>${urlInput}</strong>:<br>
                    <strong>Estado:</strong> ${result.status}<br>
                    <strong>Caducidad:</strong> ${result.validTo}`;
                actionButtons.style.display = "block";
                urlCertificateDetails = result.certificate;
                urlPublicKeyDetails   = result.publicKey;
            }
        } catch (error) {
            resultDiv.style.display = "block";
            resultDiv.textContent   = "Error al comprobar el certificado.";
            actionButtons.style.display = "none";
        }
    }

    // Mostrar contenido de un certificado local (show_certificate.php)
    async function showCertificateContent(certPath) {
        const certDetailsDiv = document.getElementById("certDetails");

        try {
            const response = await fetch("show_certificate.php", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ certPath })
            });

            const result = await response.json();

            if (result.error) {
                certDetailsDiv.textContent = `Error: ${result.error}`;
            } else {
                certDetailsDiv.textContent = result.certificate;
            }

            certDetailsDiv.style.display = "block";
        } catch (error) {
            certDetailsDiv.textContent = "Error al obtener el contenido del certificado.";
            certDetailsDiv.style.display = "block";
        }
    }

    // Mostrar contenido de un certificado remoto (show_remote_certificate.php)
    async function showRemoteCertificateContent(domain) {
        const certDetailsDiv = document.getElementById("certDetails");

        try {
            const response = await fetch("show_remote_certificate.php", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ domain })
            });

            const result = await response.json();

            if (result.error) {
                certDetailsDiv.textContent = `Error: ${result.error}`;
            } else {
                certDetailsDiv.textContent = result.certificate
                    || "No se pudo obtener el contenido del certificado remoto.";
            }

            certDetailsDiv.style.display = "block";
        } catch (error) {
            certDetailsDiv.textContent = "Error al obtener el contenido del certificado remoto.";
            certDetailsDiv.style.display = "block";
        }
    }

    // Mostrar detalles del certificado de la URL (check_certificate.php)
    function showCertificateDetails() {
        const certDetailsDiv = document.getElementById("certDetails");
        certDetailsDiv.textContent = urlCertificateDetails || "No hay detalles del certificado disponibles.";
        certDetailsDiv.style.display = "block";
    }

    // Mostrar detalles de la clave pública (check_certificate.php)
    function showPublicKeyDetails() {
        const certDetailsDiv = document.getElementById("certDetails");
        certDetailsDiv.textContent = urlPublicKeyDetails || "No hay detalles de la clave pública disponibles.";
        certDetailsDiv.style.display = "block";
    }

    // Limpiar resultados del checker manual
    function clearResults() {
        document.getElementById("urlResult").style.display    = "none";
        document.getElementById("urlResult").textContent      = "";
        document.getElementById("certDetails").style.display  = "none";
        document.getElementById("certDetails").textContent    = "";
        document.getElementById("urlActionButtons").style.display = "none";
        document.getElementById("urlInput").value = "";
    }
</script>

</body>
</html>
