# CertViewExpire

Aplicación en PHP para visualizar el estado de los certificados

## Características

- **Almacenamiento de certificados**: Guarda y organiza tus certificados en la carpeta `certificados`.
- **Monitoreo de fechas de expiración**: Realiza un seguimiento de las fechas de caducidad.
- **Interfaz sencilla**: Permite una interacción amigable para consultar rápidamente la información de cada certificado.

## Requisitos

- `PHP 7.4 o superior y openssl`

## Despliegue en docker

- `git clone https://github.com/Aleixenandros/CertViewExpire.git`
- `docker compose up -d`

Y accede por http://localhost:8000 o cambia el puerto en el docker compose por el que quieras. Si tienes más instancias docker, puedes crear un proxy inverso con nginx.



![image](https://github.com/user-attachments/assets/089b81ba-f093-4d2f-9d9b-0b1056cfc42d)

