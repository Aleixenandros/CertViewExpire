<?php

function ldap_authenticate($username, $password, $ldapConfig) {
    $ldapconn = ldap_connect($ldapConfig['server'], $ldapConfig['port']);
    if (!$ldapconn) {
        throw new Exception("No se pudo conectar al servidor LDAP");
    }
    ldap_set_option($ldapconn, LDAP_OPT_PROTOCOL_VERSION, 3);
    ldap_set_option($ldapconn, LDAP_OPT_REFERRALS, 0);

    // Si 'user_dn' está definido, construir el DN del usuario directamente
    if (!empty($ldapConfig['user_dn'])) {
        $userDN = "uid={$username}," . $ldapConfig['user_dn'] . "," . $ldapConfig['base_dn'];
    } else {
        // Realizar una búsqueda en el base_dn para encontrar el DN del usuario
        $searchFilter = "(uid={$username})";
        $search = ldap_search($ldapconn, $ldapConfig['base_dn'], $searchFilter);
        $entries = ldap_get_entries($ldapconn, $search);
        if ($entries["count"] > 0) {
            $userDN = $entries[0]["dn"];
        } else {
            // Usuario no encontrado en el directorio
            return false;
        }
    }

    // Intentar el bind (autenticación) con el DN obtenido
    if (@ldap_bind($ldapconn, $userDN, $password)) {
        return true;
    }
    return false;
}
?>
