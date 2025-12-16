import nmap
import sys

nm = nmap.PortScanner()
target_ip = "135.237.157.135"

def scan_target():
    print(f"Escaneando la máquina objetivo: {target_ip}")
    try:
        nm.scan(hosts=target_ip, ports="22,80-443", arguments="-Pn -sV -sS --reason")

        print("Comando ejecutado:", nm.command_line())

        print(f"\nResultados del escaneo para {target_ip}:")
        print(f"Estado: {nm[target_ip].state()}")
        print(f"Protocolos detectados: {nm[target_ip].all_protocols()}")

        for proto in nm[target_ip].all_protocols():
            print(f"\nProtocolo: {proto}")
            for port in sorted(nm[target_ip][proto].keys()):
                pd = nm[target_ip][proto][port]
                state = pd.get("state", "unknown")
                reason = pd.get("reason", "")
                name = pd.get("name", "")
                product = pd.get("product", "")
                version = pd.get("version", "")
                extrainfo = pd.get("extrainfo", "")

                service = " ".join(x for x in [name, product, version, extrainfo] if x) or "unknown"
                print(f"Puerto: {port} - Estado: {state} ({reason}) - {service}")

        with open("scan_results.txt", "w", encoding="utf-8") as f:
            f.write(f"Escaneo de {target_ip}\n")
            f.write(f"Comando ejecutado: {nm.command_line()}\n")
            f.write(f"Estado: {nm[target_ip].state()}\n")
            for proto in nm[target_ip].all_protocols():
                f.write(f"\nProtocolo: {proto}\n")
                for port in sorted(nm[target_ip][proto].keys()):
                    pd = nm[target_ip][proto][port]
                    service = " ".join(x for x in [
                        pd.get("name",""), pd.get("product",""),
                        pd.get("version",""), pd.get("extrainfo","")
                    ] if x) or "unknown"
                    f.write(f"Puerto: {port} - {pd.get('state','unknown')} ({pd.get('reason','')}) - {service}\n")

        print("\nResultados guardados en 'scan_results.txt'")

    except Exception as e:
        print(f"Error durante el escaneo: {e}")
        sys.exit(1)

if __name__ == "__main__":
    scan_target()
