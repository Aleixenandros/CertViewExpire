<?php
return [
    // 'directory' => Lee archivos .cer de una carpeta
    // 'txt'       => Lee dominios de un archivo de texto y verifica el certificado remoto
    // Puede ser ['directory'], ['txt'] o ['directory', 'txt'] si quieres ambos
    'read_mode' => ['directory', 'txt'],

    // Carpeta con archivos .cer (solo se usa si read_mode='directory')
    'cert_directory' => './certificados/',

    // Fichero de texto con un listado de dominios (uno por línea)
    // (solo se usa si read_mode='txt')
    'domains_file' => './certificados/dominios.txt',
    
    // Autenticación por LDAP
    'login_method' => 'NO', // Opciones: 'LDAP' o 'NO'
    'ldap' => [
        'server'   => 'ldap://ldap.ejemplo.com',
        'port'     => 389,
        'base_dn'  => 'dc=ejemplo,dc=es',
        'user_dn'  => 'ou=usuarios'
		],
    // Días para considerar "próxima expiración"
    'prox_expir' => 45,
];

