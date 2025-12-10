from scapy.all import sniff, TCP, IP, get_if_addr, conf
import logging
import time
import os

# Variables de configuración
LOG_FILE = "sniffer_defense.log"
BLOCKED_IPS_FILE = "blocked_ips.txt"
SYN_THRESHOLD = 5       # número de SYN en la ventana para considerar sospechoso
TIME_WINDOW = 10        # ventana de tiempo en segundos

# Intentar obtener la IP local automáticamente para ignorarla
try:
    MY_IP = get_if_addr(conf.iface)
except:
    # Fallback manual si falla la detección
    MY_IP = "192.168.0.31"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# Diccionario para rastrear SYN por IP
syn_tracker = {}


def detect_suspicious_activity(packet):
    """Detecta paquetes TCP SYN y registra actividad sospechosa."""
    if packet.haslayer(TCP) and packet.haslayer(IP):
        src_ip = packet[IP].src

        # 1. Ignorar nuestro propio tráfico
        if src_ip == MY_IP:
            return

        # 2. STRICT SYN CHECK (flags == 0x02 → SYN)
        if packet[TCP].flags == 0x02:
            dst_port = packet[TCP].dport

            msg = (
                f"ALERTA: Intento de conexión (SYN) desde {src_ip} "
                f"hacia tu puerto {dst_port}"
            )
            print(f"[DETECTADO] {msg}")
            logging.info(msg)

            # Lógica de detección de escaneo
            current_time = time.time()
            if src_ip not in syn_tracker:
                syn_tracker[src_ip] = []

            # Mantener solo los SYN dentro de la ventana de tiempo
            syn_tracker[src_ip] = [
                t for t in syn_tracker[src_ip]
                if current_time - t < TIME_WINDOW
            ]
            syn_tracker[src_ip].append(current_time)

            # Si supera o iguala el umbral, marcar como sospechoso
            if len(syn_tracker[src_ip]) >= SYN_THRESHOLD:
                alert_msg = (
                    f"PELIGRO: Posible escaneo de puertos desde {src_ip} "
                    f"({len(syn_tracker[src_ip])} intentos en {TIME_WINDOW}s)"
                )
                print(f"\n[!!!] {alert_msg}")
                logging.warning(alert_msg)

                # Guardar IP sospechosa en archivo
                try:
                    with open(BLOCKED_IPS_FILE, "a") as f:
                        f.write(
                            f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {src_ip}\n"
                        )
                except Exception as e:
                    print(
                        f"[ERROR] No se pudo escribir en {BLOCKED_IPS_FILE}: {e}"
                    )

                # Acción de bloqueo sugerida (Windows netsh, ajústalo si usas Linux)
                print(
                    "[SUGERENCIA] Bloquear IP: "
                    f"netsh advfirewall firewall add rule "
                    f"name=\"Block {src_ip}\" dir=in action=block remoteip={src_ip}"
                )

                # Reiniciar contador para esa IP después de la alerta
                syn_tracker[src_ip] = []


if __name__ == "__main__":
    print("Iniciando Sniffer de Defensa (Mejorado)...")
    print(f"Ignorando tráfico propio desde: {MY_IP}")
    print("Esperando conexiones entrantes sospechosas...\n")
    sniff(filter="tcp", prn=detect_suspicious_activity, store=0)
