import subprocess
import os
from datetime import datetime

LOG_FILE = "log_events.txt"
LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), LOG_FILE)

def run_command(command, description):
    print(f"\n--- Ejecutando auditoría: {description} ---")
    try:
 
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            shell=False
        )
        return process.stdout
    except subprocess.CalledProcessError as e:
        return f"ERROR al ejecutar '{' '.join(command)}': {e.stderr}"
    except FileNotFoundError:
        return f"ERROR: Comando no encontrado. ¿Está instalado '{command[0]}'?"

def perform_os_audit():
    
    audit_results = f"*** Auditoría de Seguridad Iniciada: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ***\n\n"

    audit_results += "===== 1. PUERTOS ABIERTOS Y SERVICIOS EN ESCUCHA (ss -tuln) =====\n"
    ports_command = ["ss", "-tuln"]
    audit_results += run_command(ports_command, "Puertos abiertos")
    audit_results += "\n"

 
    audit_results += "===== 2. LISTADO DE USUARIOS DEL SISTEMA (/etc/passwd) =====\n"
    users_command = ["cat", "/etc/passwd"]
    audit_results += run_command(users_command, "Usuarios del sistema")
    audit_results += "\n"
    
   
    audit_results += "===== 3. SERVICIOS ACTIVOS (ps aux | head) =====\n"
    
    services_command = ["ps", "aux"]
    audit_results += run_command(services_command, "Servicios en ejecución (Primeras lineas)")
    audit_results += "\n"
    
    audit_results += "===== 4. ÚLTIMOS ACCESOS AL SISTEMA (last -n 10) =====\n"
    last_command = ["last", "-n", "10"]
    audit_results += run_command(last_command, "Últimos 10 accesos")
    audit_results += "\n"
    
    return audit_results

def log_results(results):
    try:
        with open(LOG_PATH, "a") as f:
            f.write(results)
        print(f"\n[ÉXITO] Resultados guardados en: {LOG_PATH}")
    except Exception as e:
        print(f"\n[ERROR] No se pudo escribir en el archivo de log: {e}")

if __name__ == "__main__":
    print("Iniciando auditoría de seguridad para Blue Team...")
    
    audit_output = perform_os_audit()

    log_results(audit_output)
    
    print("\nAuditoría de Blue Team finalizada.")