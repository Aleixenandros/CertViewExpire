<?php
// 1. Cargar la configuración
$config = include 'config.php';

// Si se usa LDAP y no hay usuario autenticado, redirige a login.php
if ($config['login_method'] === 'LDAP' && (!isset($_SESSION['authenticated']) || $_SESSION['authenticated'] !== true)) {
    header("Location: login.php");
    exit;
}

// 2. Obtener parámetros
$readModes   = $config['read_mode']      ?? ['directory'];
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
 * Recibe $config para leer 'prox_expir'.
 */
function getLocalCertificateInfo($certPath, $config)
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

    // Obtenemos el umbral definido en config.php (por defecto 45)
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
 * Analiza un certificado remoto (conectando por SSL a un dominio).
 * Devuelve [status, fechaExpiración, estadoCss].
 * Recibe $config para leer 'prox_expir'.
 */
function getRemoteCertificateInfo($domain, $config)
{
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

// ==============================================================================
// 4. Agrupar certificados LOCALES (carpeta raíz + subcarpetas)
// ==============================================================================
$localCategories = [];
$localCategories['RAIZ'] = []; // Para .cer de la carpeta principal

if (in_array('directory', $readModes)) {
    if (!is_dir($directory)) {
        die("Error: la carpeta '{$directory}' no existe o no es válida.");
    }

    // Escanear la carpeta base en busca de .cer sueltos
    $rootItems = array_diff(scandir($directory), ['.', '..']);
    $rootCer = array_filter($rootItems, function($f) use ($directory) {
        $fullPath = $directory . DIRECTORY_SEPARATOR . $f;
        return is_file($fullPath) && pathinfo($fullPath, PATHINFO_EXTENSION) === 'cer';
    });
    foreach ($rootCer as $cerFile) {
        $fullPath = $directory . DIRECTORY_SEPARATOR . $cerFile;
        $localCategories['RAIZ'][] = $fullPath;
    }

    // Escanear subcarpetas
    foreach ($rootItems as $possibleDir) {
        $subPath = $directory . DIRECTORY_SEPARATOR . $possibleDir;
        if (!is_dir($subPath)) continue;
        if ($possibleDir === '.' || $possibleDir === '..') continue;

        $categoryName = $possibleDir;
        $localCategories[$categoryName] = [];

        $subItems = array_diff(scandir($subPath), ['.', '..']);
        $cerInSub = array_filter($subItems, function($f) use ($subPath) {
            $fp = $subPath . DIRECTORY_SEPARATOR . $f;
            return is_file($fp) && pathinfo($fp, PATHINFO_EXTENSION) === 'cer';
        });

        foreach ($cerInSub as $cerFile) {
            $fullPath = $subPath . DIRECTORY_SEPARATOR . $cerFile;
            $localCategories[$categoryName][] = $fullPath;
        }
    }
}

// ==============================================================================
// 5. Leer dominios REMOTOS (fichero .txt), como antes
// ==============================================================================
$certificateItemsRemote = [];
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
    <!-- Referencia al CSS externo -->
    <link rel="stylesheet" href="css/style.css">
</head>
<body>

    <?php
    // Mostrar el mensaje de bienvenida y enlace de logout solo si se usa LDAP y el usuario está autenticado
    if ($config['login_method'] === 'LDAP' && isset($_SESSION['username'])) {
        
	echo '<header class="topbar">';
	echo "Bienvenido, " . htmlspecialchars($_SESSION['username']);
        echo '<a href="logout.php">Salir</a>';
	echo "</header>";
    }
    ?>

<div class="container">
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

    <table id="certificatesTable">
        <thead>
            <tr>
                <th>Certificado / Dominio</th>
                <th>Caducidad</th>
                <th>Estado</th>
                <th>Acción</th>
            </tr>
        </thead>

        <!-- Certificados locales -->
        <tbody id="tbodyLocal">
        <?php
        if (!empty($localCategories)) {
            echo "<tr><th colspan='4' style='background-color:#ccc;'>Certificados locales</th></tr>";

            foreach ($localCategories as $categoryName => $filePaths) {
                // No mostramos encabezado si es la raíz
                if ($categoryName !== 'RAIZ') {
                    echo "<tr class='category-header'><th colspan='4'>Categoría: {$categoryName}</th></tr>";
                }

                if (empty($filePaths)) {
                    echo "<tr><td colspan='4'><em>No hay archivos .cer en esta subcarpeta.</em></td></tr>";
                    continue;
                }

                // Llamamos a getLocalCertificateInfo pasando $config
                foreach ($filePaths as $cerPath) {
                    $fileName = basename($cerPath);
                    list($status, $expiryDate, $state) = getLocalCertificateInfo($cerPath, $config);

                    $total++;
                    if ($state === "valid")    $valid++;
                    if ($state === "expiring") $expiring++;
                    if ($state === "expired")  $expired++;

                    $buttonAction = "showCertificateContent('{$cerPath}')";
                    echo "<tr class='{$state}'>
                            <td>{$fileName}</td>
                            <td>{$expiryDate}</td>
                            <td>{$status}</td>
                            <td><button onclick=\"{$buttonAction}\">Mostrar Certificado</button></td>
                          </tr>";
                }
            }
        }
        ?>
        </tbody>

        <!-- Certificados remotos -->
        <tbody id="tbodyRemote">
        <?php if (!empty($certificateItemsRemote)): ?>
            <tr><th colspan="4" style="background-color:#ccc;">Certificados remotos (dominios)</th></tr>
            <?php
            foreach ($certificateItemsRemote as $item) {
                // Llamamos a getRemoteCertificateInfo pasando $config
                list($status, $expiryDate, $state) = getRemoteCertificateInfo($item['source'], $config);

                $total++;
                if ($state === "valid")    $valid++;
                if ($state === "expiring") $expiring++;
                if ($state === "expired")  $expired++;

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
    // Pintamos los contadores en la interfaz
    document.getElementById("totalCertificates").textContent    = <?php echo $total; ?>;
    document.getElementById("validCertificates").textContent    = <?php echo $valid; ?>;
    document.getElementById("expiringCertificates").textContent = <?php echo $expiring; ?>;
    document.getElementById("expiredCertificates").textContent  = <?php echo $expired; ?>;

    let urlCertificateDetails = "";
    let urlPublicKeyDetails   = "";

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

    function showCertificateDetails() {
        const certDetailsDiv = document.getElementById("certDetails");
        certDetailsDiv.textContent = urlCertificateDetails || "No hay detalles del certificado disponibles.";
        certDetailsDiv.style.display = "block";
    }

    function showPublicKeyDetails() {
        const certDetailsDiv = document.getElementById("certDetails");
        certDetailsDiv.textContent = urlPublicKeyDetails || "No hay detalles de la clave pública disponibles.";
        certDetailsDiv.style.display = "block";
    }

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

