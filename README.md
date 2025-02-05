# CertViewExpire

Aplicación en PHP para visualizar el estado de los certificados

## Características

- **Almacenamiento de certificados**: Guarda y organiza tus certificados en la carpeta `certificados`.
- **Monitoreo de fechas de expiración**: Realiza un seguimiento de las fechas de caducidad.
- **Interfaz sencilla**: Permite una interacción amigable para consultar rápidamente la información de cada certificado.

## Requisitos

- `PHP 7.4 o superior y openssl`

## config.php

En el config.php puedes configurar dónde está la carpeta de `certificados` si dónde se ubica el `dominios.txt`, si quieres que sólo muestre los certificados que hay en la carpeta, que muestre los certificados de los dominios que tienes en el `dominios.txt` o puedes elegir ambos.
También puedes configurar la fecha de "próxima expiración", que por defecto está en 45: 'prox_expir => 45'

## Despliegue en docker

- `git clone https://github.com/Aleixenandros/CertViewExpire.git`
- `docker compose up -d`

Y accede por http://localhost:8000 o cambia el puerto en el `docker-compose.yml` por el que quieras. Si tienes más instancias docker, puedes crear un proxy inverso con nginx.



![image](https://github.com/user-attachments/assets/089b81ba-f093-4d2f-9d9b-0b1056cfc42d)

