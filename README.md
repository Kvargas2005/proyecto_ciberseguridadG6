# Proyecto Final — Red Team vs Blue Team en Azure

Este proyecto implementa un entorno práctico de ciberseguridad donde dos equipos, **Red Team** (atacante) y **Blue Team** (defensor), interactúan sobre una máquina virtual (VM) desplegada en **Microsoft Azure**.  
El objetivo es simular un escenario real de ataque y defensa, documentando técnicas ofensivas y mecanismos de detección.

---

## 📌 Objetivos del Proyecto

- Simular ataques reales utilizando herramientas de red.
- Desarrollar un sistema básico de detección (IDS) capaz de identificar patrones maliciosos.
- Registrar y evidenciar el tráfico generado entre atacante y servidor.
- Aplicar buenas prácticas de seguridad y proponer recomendaciones de mejora.

---

## 🟥 Red Team (Atacante)

El Red Team intenta comprometer o reconocer la VM mediante:

### **1. scanner.py**
Script que realiza un escaneo básico de puertos sobre la IP pública de la VM para identificar servicios expuestos.

### **2. packet_attack.py**
Implementa un ataque tipo **SYN Flood**, enviando múltiples paquetes TCP con la bandera SYN al puerto objetivo (ej. 22 o 80).  
El propósito es simular tráfico malicioso y provocar conexiones semiabiertas.

---

## 🟦 Blue Team (Defensor)

El Blue Team despliega un mecanismo de detección en la VM:

### **1. sniffer_defense.py**
Sniffer en Python con Scapy que:
- Monitorea paquetes entrantes.
- Detecta patrones sospechosos (múltiples SYN).
- Registra actividad anómala.
- Genera alertas de posible ataque o escaneo.
- Sugiere acciones defensivas (ej. bloqueo de IP).

---

## 📂 Estructura del Proyecto



proyecto_ciberseguridadG6/
├── blue_team/
│ ├── firewall_basic.sh # Configuración de firewall
│ ├── sniffer_defense.py # Detección de tráfico
│ ├── os_audit.py # Auditoría de sistema
│ └── log_events.txt # Auditoría de sistema
├── red_team/
│ ├── scanner.py # Escaneo de puertos
│ └──packet_attack.py # Sniffing y ARP Spoofing
└── README.md


## Cómo Correr

1. **Blue Team**:
   - Ejecuta los scripts de defensa (por ejemplo, `python3 sniffer_defense.py`) 
   
2. **Red Team**:
   - Ejecuta los scripts de ataque (por ejemplo, `python3 red_team/scanner.py y packet_atack.py`) para escanear la VM y buscar vulnerabilidades.

## Evaluación

- **Blue Team**: Éxito si logra proteger la VM y detectar ataques.
- **Red Team**: Éxito si logra vulnerar la VM y documentar sus métodos.
