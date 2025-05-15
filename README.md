# Config Sanitizer Tool
English Version
![](https://github.com/leonelpedroza/ip_monitor/blob/main/UKFlag.png)

## History

In many of my roles installing and maintaining network equipment, I've had to interact with suppliers and manufacturers of communications equipment on several occasions regarding unexpected behaviour and specific inquiries. In almost every case, the support engineer requests a copy of the equipment configuration.

In my usual cybersecurity paranoia, I never found it very convenient to send configuration files and leave them "_into the wild_" on the internet.

I created this program about three years ago to clean sensitive data from configurations, setups, and event logs before sending them. This information mainly includes passwords, usernames, encryption keys, and tokens, among other things.

This Python program has covered my basic needs for quite some time, so I asked my friend Claude AI LLM to organize it, add comments, improve error handling, make it more modular and readable, and adhere to the Python PEP-8 programming standard.


## Introduction

A powerful, user-friendly tool for sanitizing network device configuration files by removing sensitive information like passwords, certificates, keys, and authentication credentials.

![](https://github.com/leonelpedroza/Sanitizzer/blob/main/Screenshot.png)

## Features

- **Multi-Vendor Support**: Sanitizes configuration files from Cisco, Fortinet, Juniper, Huawei, Palo Alto, and Gigamon devices.
- **Auto-Detection**: Automatically identifies device type from configuration content.
- **Preview Mode**: Side-by-side comparison of original and sanitized content before making changes.
- **External Password Management**: Define custom sensitive passwords in an external file.
- **Automatic Backup**: Creates backups of original files before sanitization.
- **Multi-threading**: Responsive UI during sanitization of large files.
- **Comprehensive Logging**: Detailed logs of all operations.

## Why Config Sanitizer?

Network engineers often need to share configuration files with vendors, colleagues, or support teams. However, these files typically contain sensitive credentials and keys that shouldn't be exposed. Config Sanitizer automatically removes this sensitive information while preserving the structure of the configuration file, making it safe to share.

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/config-sanitizer.git

# Navigate to the project directory
cd config-sanitizer

# Install dependencies (if required)
pip install -r requirements.txt

# Run the application
python sanitizer.py
```

## Usage

1. Launch the application
2. Select a configuration file using the "Browse Files" button
3. Choose a device type or use auto-detection
4. Click "Preview" to see what will be changed
5. Click "SANITIZE" to process the file
6. A sanitized version of your file will be saved with timestamp in the same directory

## Supported Patterns

The tool sanitizes the following sensitive information:

- Passwords and secrets
- SNMP community strings
- Authentication keys
- SSH keys
- Certificates and encrypted content
- API tokens
- Shared secrets
- And much more!

## Customization

- Add your own passwords to the `secret.txt` file
- Edit vendor-specific patterns in the code
- Contribute additional vendor support by adding new sanitization methods

## Requirements

- Python 3.6+
- Tkinter (included with most Python installations)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Originally created by lgp DevOps (March 2022)
- Enhanced version with additional features (2025)



__________________________________________________________
__________________________________________________________


# Config Sanitizer Tool

Español
![](https://github.com/leonelpedroza/ip_monitor/blob/main/SpainFlag.png)

## Historia
En bastantes de mis funciones, instalando y manteniendo equipos de redes, en varias ocasiones he tenido que interactuar con proveedores y fabricantes de equipos de comunicaciones por casos y consultas puntuales respecto a comportamientos no esperados y, en casi todos los casos, el ingeniero de soporte solicita una copia de la configuración del equipo.

En mi acostumbrada paranoia en ciberseguridad, nunca encontré muy conveniente estar enviado archivos de configuración dejándolos a “merced del viento” en internet.

Hice este programa hace unos tres años para limpiar de algunos datos sensibles de las configuraciones, setup, y logs de eventos antes de enviarlos. Información principalmente de contraseñas, nombres de usuarios, llaves de encriptación y tokens entre otros.

Este programa de Python lleva bastante tiempo cubriendo mis necesidades básicas así que le pedí a mi amiga ClaudeAI LLM que me lo ordenara, le colocara comentarios, mejorara el manejo de errores, lo hiciera más modular, legible, y lo adhiriera al estándar de programación PEP 8 Python



## Introducción

Una herramienta potente y fácil de usar para sanitizar archivos de configuración de dispositivos de red mediante la eliminación de información sensible como contraseñas, certificados, claves y credenciales de autenticación.

![](https://github.com/leonelpedroza/ip_monitor/blob/main/Screenshot.png)

## Características

- **Soporte Multi-Fabricante**: Sanitiza archivos de configuración de dispositivos Cisco, Fortinet, Juniper, Huawei, Palo Alto y Gigamon.
- **Detección Automática**: Identifica automáticamente el tipo de dispositivo a partir del contenido de la configuración.
- **Modo Vista Previa**: Comparación lado a lado del contenido original y sanitizado antes de realizar cambios.
- **Gestión de Contraseñas Externa**: Define contraseñas sensibles personalizadas en un archivo externo.
- **Respaldo Automático**: Crea copias de seguridad de los archivos originales antes de la sanitización.
- **Multi-threading**: Interfaz de usuario responsive durante la sanitización de archivos grandes.
- **Registro Completo**: Registros detallados de todas las operaciones.

## ¿Por qué Config Sanitizer?

Los ingenieros de redes a menudo necesitan compartir archivos de configuración con proveedores, colegas o equipos de soporte. Sin embargo, estos archivos típicamente contienen credenciales sensibles y claves que no deberían exponerse. Config Sanitizer elimina automáticamente esta información sensible mientras preserva la estructura del archivo de configuración, haciéndolo seguro para compartir.

## Instalación

```bash
# Clonar el repositorio
git clone https://github.com/tunombredeusuario/config-sanitizer.git

# Navegar al directorio del proyecto
cd config-sanitizer

# Instalar dependencias (si se requiere)
pip install -r requirements.txt

# Ejecutar la aplicación
python sanitizer.py
```

## Uso

1. Inicia la aplicación
2. Selecciona un archivo de configuración usando el botón "Browse Files"
3. Elige un tipo de dispositivo o usa la detección automática
4. Haz clic en "Preview" para ver qué será cambiado
5. Haz clic en "SANITIZE" para procesar el archivo
6. Una versión sanitizada de tu archivo se guardará con marca de tiempo en el mismo directorio

## Patrones Soportados

La herramienta sanitiza la siguiente información sensible:

- Contraseñas y secretos
- Cadenas de comunidad SNMP
- Claves de autenticación
- Claves SSH
- Certificados y contenido encriptado
- Tokens API
- Secretos compartidos
- ¡Y mucho más!

## Personalización

- Añade tus propias contraseñas al archivo `secret.txt`
- Edita patrones específicos del fabricante en el código
- Contribuye con soporte adicional para fabricantes añadiendo nuevos métodos de sanitización

## Requisitos

- Python 3.6+
- Tkinter (incluido con la mayoría de instalaciones de Python)

## Contribuir

¡Las contribuciones son bienvenidas! No dudes en enviar un Pull Request.

1. Haz un fork del repositorio
2. Crea tu rama de características (`git checkout -b feature/caracteristica-asombrosa`)
3. Haz commit de tus cambios (`git commit -m 'Añadir alguna característica asombrosa'`)
4. Haz push a la rama (`git push origin feature/caracteristica-asombrosa`)
5. Abre un Pull Request

## Licencia

Este proyecto está licenciado bajo la Licencia MIT - consulta el archivo [LICENSE](LICENSE) para más detalles.

## Agradecimientos

- Creado originalmente por lgp DevOps (Marzo 2022)
- Versión mejorada con características adicionales (2025)
