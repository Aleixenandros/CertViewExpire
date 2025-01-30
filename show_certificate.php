<?php
header('Content-Type: application/json; charset=utf-8');

$input = json_decode(file_get_contents('php://input'), true);
$certPath = $input['certPath'] ?? null;

if (!$certPath) {
    echo json_encode(['error' => 'No se recibió la ruta del certificado.']);
    exit;
}

// Verificar que el archivo existe
if (!file_exists($certPath)) {
    echo json_encode(['error' => "El archivo no existe: $certPath"]);
    exit;
}

$content = file_get_contents($certPath);
if ($content === false) {
    echo json_encode(['error' => "Error al leer el certificado."]);
    exit;
}

// Exportar a PEM (por si no lo está)
$pem = '';
if (!openssl_x509_export($content, $pem)) {
    // Si falla, quizá era ya un PEM
    $pem = $content;
}

echo json_encode(['certificate' => $pem]);

