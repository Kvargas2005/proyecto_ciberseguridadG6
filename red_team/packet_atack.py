from scapy.all import IP, TCP, send, sr1, ICMP, conf
import time
import random
import sys

target_ip = "135.237.157.135"  # IP de la maquina virtual
target_port = 22  # Puerto a atacar
check_interval = 5  # Verificar estado cada X paquetes
timeout = 1.5  # Timeout para respuestas (reducido para ser más rápido)
max_retries = 2  # Reintentos para verificación

# Configurar verbosidad de Scapy
conf.verb = 0

print(f"Enviando y verificando peticiones SYN a {target_ip}:{target_port}")
print("="*60)

def check_vm_alive():
    """Verifica si la VM está activa enviando un ping (ICMP)"""
    try:
        packet = IP(dst=target_ip)/ICMP()
        response = sr1(packet, timeout=timeout, verbose=0)
        return response is not None
    except Exception as e:
        print(f"Error al verificar VM: {e}")
        return False

def send_and_verify_syn():
    """Envía un SYN y verifica si hay respuesta"""
    sport = random.randint(1024, 65535)
    seq = random.randint(1000, 9000)
    
    # Crear paquete SYN
    packet = IP(dst=target_ip)/TCP(
        sport=sport,
        dport=target_port,
        flags="S",
        seq=seq
    )
    
    try:
        # Enviar y esperar respuesta
        response = sr1(packet, timeout=timeout, verbose=0, retry=0)
        
        if response is None:
            return None, "No response"
        
        if response.haslayer(TCP):
            if response[TCP].flags == "SA":  # SYN-ACK
                # Opcional: Enviar RST para cerrar la conexión limpia
                rst_packet = IP(dst=target_ip)/TCP(
                    sport=sport,
                    dport=target_port,
                    flags="R",
                    seq=seq + 1,
                    ack=response[TCP].seq + 1
                )
                send(rst_packet, verbose=0)
                return response, "SYN-ACK"
            
            elif response[TCP].flags == "RA":  # RST-ACK
                return response, "RST"
            
            elif response[TCP].flags == "R":  # RST
                return response, "RST"
            
            else:
                return response, f"Other flags: {response[TCP].flags}"
        
        elif response.haslayer(ICMP):
            icmp_type = response[ICMP].type
            if icmp_type == 3:  # Destination Unreachable
                return response, "ICMP Unreachable"
            return response, f"ICMP Type {icmp_type}"
        
        else:
            return response, "Unknown response"
            
    except Exception as e:
        return None, f"Error: {e}"

# Estadísticas
stats = {
    'total_sent': 0,
    'total_received': 0,
    'syn_ack': 0,
    'rst': 0,
    'no_response': 0,
    'other': 0,
    'errors': 0
}

# Verificación inicial
print("\n[INICIO] Verificando estado del objetivo...")
vm_alive = check_vm_alive()
print(f"VM responde a ping: {'SÍ' if vm_alive else 'NO'}")

# Prueba inicial de conexión
print("\n[PRUEBA] Enviando SYN de prueba...")
response, status = send_and_verify_syn()
print(f"Estado puerto {target_port}: {status}")

if status == "No response" and not vm_alive:
    print("\n ADVERTENCIA: El objetivo no responde. Puede estar:")
    print("   - Apagado/desconectado")
    print("   - Con firewall bloqueando todo")
    print("   - Inalcanzable por red")
    print("\nContinuando envío para monitoreo...")

print("\n" + "="*60)
print("Iniciando envío con verificación en tiempo real...")
print("="*60)

try:
    packet_count = 0
    
    while True:
        packet_count += 1
        stats['total_sent'] += 1
        
        print(f"\n[Paquete #{packet_count}] ", end="")
        
        # Enviar y verificar
        start_time = time.time()
        response, status = send_and_verify_syn()
        response_time = (time.time() - start_time) * 1000  # ms
        
        # Actualizar estadísticas
        if status == "SYN-ACK":
            stats['syn_ack'] += 1
            stats['total_received'] += 1
            print(f"RECIBIDO - SYN-ACK en {response_time:.1f}ms")
            print(f"  Puerto {target_port} ABIERTO")
            
        elif status == "RST":
            stats['rst'] += 1
            stats['total_received'] += 1
            print(f"RECIBIDO - RST en {response_time:.1f}ms")
            print(f"  Puerto {target_port} CERRADO/Rechazado")
            
        elif "ICMP" in status:
            stats['other'] += 1
            stats['total_received'] += 1
            print(f"  RECIBIDO - {status} en {response_time:.1f}ms")
            
        elif status == "No response":
            stats['no_response'] += 1
            print(f"SIN RESPUESTA (timeout: {timeout}s)")
            
        else:
            stats['errors'] += 1
            print(f"  {status}")
        
        # Verificación periódica de la VM
        if packet_count % check_interval == 0:
            print(f"\n{'─'*40}")
            print(f"[MONITOR] Verificación #{packet_count//check_interval}")
            
            # Verificar si VM sigue viva
            vm_status = check_vm_alive()
            print(f"  Estado VM: {'ACTIVA' if vm_status else 'INACTIVA'}")
            
            # Mostrar estadísticas parciales
            print(f"  Paquetes: {stats['total_sent']} enviados")
            print(f"  Respuestas: {stats['total_received']} recibidas")
            
            if stats['total_sent'] > 0:
                response_rate = (stats['total_received'] / stats['total_sent']) * 100
                print(f"  Tasa respuesta: {response_rate:.1f}%")
                
                if stats['total_received'] > 0:
                    print(f"  SYN-ACK: {stats['syn_ack']} | RST: {stats['rst']}")
            
            print(f"{'─'*40}")
        
        # Pausa aleatoria
        delay = random.uniform(0.5, 2.0)
        time.sleep(delay)

except KeyboardInterrupt:
    print("\n\n" + "="*60)
    print("RESUMEN FINAL - ESTADÍSTICAS COMPLETAS")
    print("="*60)
    
    print(f"\n ESTADÍSTICAS DE ENVÍO:")
    print(f"   Total paquetes enviados: {stats['total_sent']}")
    print(f"   Total respuestas recibidas: {stats['total_received']}")
    
    if stats['total_sent'] > 0:
        response_rate = (stats['total_received'] / stats['total_sent']) * 100
        loss_rate = 100 - response_rate
        print(f"   Tasa de respuesta: {response_rate:.1f}%")
        print(f"   Tasa de pérdida: {loss_rate:.1f}%")
    
    print(f"\n TIPO DE RESPUESTAS:")
    print(f"   SYN-ACK (puerto abierto): {stats['syn_ack']}")
    print(f"   RST (puerto cerrado): {stats['rst']}")
    print(f"   Sin respuesta: {stats['no_response']}")
    print(f"   Otros/ICMP: {stats['other']}")
    print(f"   Errores: {stats['errors']}")
    
    print(f"\n CONCLUSIÓN:")
    if stats['syn_ack'] > 0:
        print("El puerto 80 está ABIERTO y responde")
        print(f"{stats['syn_ack']} conexiones SYN fueron aceptadas")
    elif stats['rst'] > 0:
        print("   El puerto 80 está CERRADO o rechaza conexiones")
        print("   El firewall/host está rechazando activamente")
    elif stats['no_response'] > 0 and stats['total_received'] == 0:
        print("     NO HAY RESPUESTA - Posibles causas:")
        print("      • IP incorrecta/inaccesible")
        print("      • Máquina apagada")
        print("      • Firewall bloqueando todo tráfico")
        print("      • Problemas de red/ruteo")
    
    print("\n" + "="*60)
    print("Programa finalizado")