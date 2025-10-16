# Proyecto Final: Red Team vs Blue Team en la Nube

## Descripción

Este proyecto simula un entorno de seguridad en Azure, donde los equipos **Red Team** (atacantes) y **Blue Team** (defensores) interactúan. El Blue Team fortalece y protege una VM, mientras que el Red Team intenta explotar vulnerabilidades en la misma.

## Roles

### Blue Team (Defensores):
- Fortalecen y protegen la VM en Azure.
- Desarrollan scripts para auditar el sistema, detectar tráfico sospechoso y realizar configuraciones de seguridad.

### Red Team (Atacantes):
- Intentan identificar vulnerabilidades en la VM usando herramientas como Nmap, Scapy y ataques de diccionario.

## Estructura del Proyecto

proyecto_ciberseguridadG6/
├── blue_team/
│ ├── firewall_hardening.sh # Configuración de firewall
│ ├── sniffer_defense.py # Detección de tráfico
│ ├── os_audit.py # Auditoría de sistema
│ └── alert_logger.py # Registro y reacciones
├── red_team/
│ ├── scanner.py # Escaneo de puertos
│ ├── packet_attack.py # Sniffing y ARP Spoofing
│ ├── ssh_brute.py # Ataque de diccionario
│ └── report.md # Documentación de ataques
└── README.md


## Cómo Correr

1. **Blue Team**:
   - Ejecuta los scripts de defensa (por ejemplo, `python3 blue_team/os_audit.py`) para auditar y proteger la VM.
   
2. **Red Team**:
   - Ejecuta los scripts de ataque (por ejemplo, `python3 red_team/scanner.py`) para escanear la VM y buscar vulnerabilidades.

## Evaluación

- **Blue Team**: Éxito si logra proteger la VM y detectar ataques.
- **Red Team**: Éxito si logra vulnerar la VM y documentar sus métodos.
