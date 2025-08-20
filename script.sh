sudo apt update -y
sudo apt upgrade -y
sudo apt install apache2

#if [ -d "/var/www/operativos" ]; then
  #echo "El directorio existe."
  sudo rm -r /var/www/operativos
#else
  sudo mkdir /var/www/operativos
  sudo touch /var/www/operativos/index.html
  echo "hola" > /var/www/operativos/index.html
#fi


sudo cp /etc/apache2/sites-available/000-default.conf  /etc/apache2/sites-available/operativos.conf
sudo sed -i 's/html/operativos/g' /etc/apache2/sites-available/operativos.conf
sudo a2dissite 000-default.conf
sudo a2ensite operativos.conf
sudo bash /etc/init.d/apache2 start
#sudo service apache2 reload





