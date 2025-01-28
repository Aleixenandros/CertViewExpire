<?php
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);

    if (!isset($input['certPath']) || empty($input['certPath'])) {
        echo json_encode(['error' => 'La ruta del certificado no está especificada.']);
        exit;
    }

    $certPath = $input['certPath'];

    if (!file_exists($certPath)) {
        echo json_encode(['error' => 'El archivo no existe.']);
        exit;
    }

    $certContent = file_get_contents($certPath);

    if ($certContent === false) {
        echo json_encode(['error' => 'No se pudo leer el archivo.']);
        exit;
    }

    echo json_encode(['certificate' => $certContent]);
} else {
    echo json_encode(['error' => 'Método no permitido.']);
}
?>

