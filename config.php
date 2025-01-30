<?php
return [
    // 'directory' => Lee archivos .cer de una carpeta
    // 'txt'       => Lee dominios de un archivo de texto y verifica el certificado remoto
    // Puede ser ['directory'], ['txt'] o ['directory', 'txt'] si quieres ambos
    'read_mode' => ['directory'],

    // Carpeta con archivos .cer (solo se usa si read_mode='directory')
    'cert_directory' => './certificados/',

    // Fichero de texto con un listado de dominios (uno por línea)
    // (solo se usa si read_mode='txt')
    'domains_file' => './certificados/domains.txt',
    
    // Días para considerar "próxima expiración"
    'prox_expir' => 45,
];

