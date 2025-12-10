import nmap
import sys

nm = nmap.PortScanner()


target_ip = "135.237.157.135"  # Reemplaza con la IP de la VM

def scan_target():
    print(f"Escaneando la máquina objetivo: {target_ip}")
    try:
        nm.scan(target_ip, '22-80,443')  #puertos a escanear

        print(f"\nResultados del escaneo para {target_ip}:")
        print(f"Estado: {nm[target_ip].state()}")
        print(f"Servicios detectados: {nm[target_ip].all_protocols()}")
        
        for proto in nm[target_ip].all_protocols():
            print(f"\nProtocolo: {proto}")
            lport = nm[target_ip][proto].keys()
            for port in lport:
                print(f"Puerto: {port} - Estado: {nm[target_ip][proto][port]['state']}")

        # Guardar los resultados en un archivo de texto
        with open("scan_results.txt", "w") as f:
            f.write(f"Escaneo de {target_ip}\n")
            f.write(f"Estado: {nm[target_ip].state()}\n")
            for proto in nm[target_ip].all_protocols():
                f.write(f"\nProtocolo: {proto}\n")
                for port in nm[target_ip][proto].keys():
                    f.write(f"Puerto: {port} - Estado: {nm[target_ip][proto][port]['state']}\n")
        print("\nResultados guardados en 'scan_results.txt'")

    except Exception as e:
        print(f"Error durante el escaneo: {e}")
        sys.exit(1)

if __name__ == "__main__":
    scan_target()

