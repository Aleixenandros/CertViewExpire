# CertViewExpire

Aplicación en PHP para visualizar el estado de los certificados

## Características

- **Almacenamiento de certificados**: Guarda y organiza tus certificados en la carpeta `certificados`.
- **Monitoreo de fechas de expiración**: Realiza un seguimiento de las fechas de caducidad.
- **Interfaz sencilla**: Permite una interacción amigable para consultar rápidamente la información de cada certificado.

## Requisitos

- `PHP 7.4 o superior y openssl`

## config.php

En el `config.php` puedes configurar dónde está la carpeta `certificados`, dónde se ubica el `dominios.txt`, si quieres que sólo muestre los certificados que hay en la carpeta, que muestre los certificados de los dominios que tienes en el `dominios.txt`, o por el contrario, que muestre ambos.

También puedes configurar la fecha de "Próximos a Caducar", que por defecto está en 45: `prox_expir => 45`

## api.php

Se añade una api que muestra una salida en json para su integración con monitorización como por ejemplo zabbix

## Despliegue en docker

- `git clone https://github.com/Aleixenandros/CertViewExpire.git`
- `docker compose up -d`

Y accede por http://localhost:8000 o cambia el puerto en el `docker-compose.yml` por el que quieras. Si tienes más instancias docker, puedes crear un proxy inverso con nginx.

![image](https://github.com/user-attachments/assets/906eb9b4-84a4-41fa-994b-945a5fa09131)


![image](https://github.com/user-attachments/assets/34b13e34-cf45-4429-b994-3e9b59b2d65f)
