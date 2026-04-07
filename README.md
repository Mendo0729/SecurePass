# SecurePass

Aplicacion de consola en Python para generar contraseñas y verificar su seguridad.

## Requisitos

- Python 3.10 o superior
- Conexion a internet para consultar Have I Been Pwned

## Instalacion

1. Abre una terminal en la carpeta del proyecto.
2. Crea un entorno virtual opcional:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

3. Instala las dependencias:

```powershell
pip install -r requirements.txt
```

## Ejecucion

Ejecuta la aplicacion con:

```powershell
python Main.py
```

## Funcionalidades

- Generacion de contrasenas seguras
- Estimacion de entropia
- Verificacion contra Have I Been Pwned

## Pruebas

Puedes ejecutar las pruebas automaticas con:

```powershell
python -m unittest
```

## Nota

Si no instalas `requests`, el proyecto no podra iniciar porque esa libreria se usa para consultar la API de contrasenas filtradas.
La entropia mostrada por la aplicacion es una estimacion y no una garantia absoluta de seguridad.
