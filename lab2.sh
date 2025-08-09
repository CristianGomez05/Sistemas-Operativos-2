# Instalar Docker
sudo apt install ca-certificates curl gnupg lsb-release -y

# Agregar la clave GPG oficial de Docker
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# Agregar el repositorio de Docker
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Actualizar de nuevo e instalar Docker
sudo apt update
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y

# Verificar que Docker funciona
sudo docker --version

# Crear la red para los contenedores
sudo docker network create misitio-net

# Crear el contenedor MariaDB
sudo docker run -d --name misitiodb \
  --network misitio-net \
  -e MYSQL_ROOT_PASSWORD=camilo.123 \
  -e MYSQL_USER=camilo \
  -e MYSQL_PASSWORD=camilo.123 \
  -e MYSQL_DATABASE=misitiodb \
  -v websitedbvolume:/var/lib/mysql \
  mariadb:latest

# Preparar el contenido web
mkdir public_html

# Creamos una página de prueba
echo "<?php phpinfo(); ?>" > public_html/index.php

# Crear el contenedor Apache + PHP
sudo docker run -d --name sitio \
  --network misitio-net \
  -v $(pwd)/public_html:/var/www/html \
  -p 8080:80 \
  php:apache

# Docker Compose
mkdir lab-contenedores
cd lab-contenedores
mkdir public_html
echo "<?php phpinfo(); ?>" > public_html/index.php

# Crear archivo docker-compose.yml
cat <<EOL > docker-compose.yml
version: '3'
services:
  sitio:
    image: php:apache
    container_name: sitio
    ports:
      - 8081:80
    volumes:
      - ./public_html:/var/www/html
    networks:
      - misitio-net
  misitiodb:
    image: mariadb:latest
    container_name: misitiodb
    volumes:
      - websitedbvolume:/var/lib/mysql
    environment:
      MYSQL_ROOT_PASSWORD: "camilo.123"
      MYSQL_USER: "camilo"
      MYSQL_PASSWORD: "camilo.123"
      MYSQL_DATABASE: "misitiodb"
    networks:
      - misitio-net
networks:
  misitio-net:
volumes:
  websitedbvolume:
EOL

# Levantar contenedores
sudo docker compose up -d

# Dockerfile
mkdir imagen-personalizada
cd imagen-personalizada
cat <<EOL > Dockerfile
FROM php:8.1-apache
RUN apt-get update && apt-get install -y \\
        libfreetype6-dev \\
        libjpeg62-turbo-dev \\
        libmcrypt-dev \\
        libicu-dev \\
        libxml2-dev \\
        vim \\
        wget \\
        unzip \\
    && docker-php-ext-install -j\$(nproc) iconv intl opcache \\
    && docker-php-ext-install -j\$(nproc) gd \\
    && docker-php-ext-install pdo_mysql exif gettext mysqli
EOL

# Construir la imagen
sudo docker build -t miprimeraimagen:v1 .

# Probar la imagen
sudo docker run -d --name prueba-imagen -p 8082:80 miprimeraimagen:v1
