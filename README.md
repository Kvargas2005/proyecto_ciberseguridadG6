# Proyecto Final de Ciberseguridad: "Red Team vs Blue Team en la Nube: Ataque y Defensa en Azure" 

## Integrantes

### **Red Team:**
- Kendall Vargas Ramírez
- Luis Palacio
- María Fernanda Bejarano

### **Blue Team:**
- Gustavo Sanabria
- Fabián Retana
- Kevin Marín

## Estructura del Repositorio

- **blue_team/**: Contiene los archivos y configuraciones del equipo defensor, incluyendo el script del firewall y documentación.
- **red_team/**: Contiene los archivos y configuraciones del equipo atacante.
- **docs/**: Documentación del proyecto, incluyendo detalles de configuración, roles, y pasos de implementación.
- **README.md**: Información general sobre el proyecto, roles del equipo y cómo ejecutar el sistema.

## Puertos Permitidos (NSG)

- **Puerto 22 (SSH)**: Permitido para permitir acceso remoto seguro a la VM a través de SSH.
- **Puerto 80 (HTTP)**: Permitido para permitir tráfico web a través del protocolo HTTP.
- **Puerto 443 (HTTPS)**: Permitido para permitir tráfico web seguro a través del protocolo HTTPS.

### **Reglas de Firewall Configuradas**
Las reglas de firewall configuradas en el **Network Security Group (NSG)** de la VM permiten únicamente los puertos mencionados. El resto del tráfico entrante está bloqueado por defecto.

## Cómo Ejecutar

1. Clona este repositorio en tu máquina local.
2. Navega a la carpeta correspondiente (`blue_team/` o `red_team/`).
3. Para ejecutar el script de firewall en la VM del **Blue Team**, navega hasta `blue_team/firewall_basic.sh` y ejecútalo:
    ```bash
    sudo bash firewall_basic.sh
    ```
4. Asegúrate de tener configurados los puertos en el **NSG** según lo mencionado.
5. Sigue las instrucciones adicionales en los archivos de cada equipo para completar la configuración.


