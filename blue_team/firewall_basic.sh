#!/bin/bash

# Denegar todo el tráfico entrante por defecto
echo "Configurando el firewall: denegando todo el tráfico entrante por defecto."
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# Permitir tráfico de loopback (localhost)
echo "Permitindo tráfico de loopback (localhost)."
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT

# Permitir tráfico SSH (Puerto 22)
echo "Permitindo tráfico en el puerto 22 (SSH)."
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Permitir tráfico HTTP (Puerto 80)
echo "Permitindo tráfico en el puerto 80 (HTTP)."
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT

# Permitir tráfico HTTPS (Puerto 443)
echo "Permitindo tráfico en el puerto 443 (HTTPS)."
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Guardar las reglas del firewall
echo "Guardando las reglas del firewall."
sudo iptables-save > /etc/iptables/rules.v4

echo "Firewall configurado correctamente."
