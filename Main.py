import secrets
import string
import math
import hashlib
import requests


def generar_contrasena(longitud, incluir_mayus, incluir_minus, incluir_numeros, incluir_simbolos):
    grupos = []
    if incluir_mayus:
        grupos.append(string.ascii_uppercase)
    if incluir_minus:
        grupos.append(string.ascii_lowercase)
    if incluir_numeros:
        grupos.append(string.digits)
    if incluir_simbolos:
        grupos.append(string.punctuation)

    if not grupos:
        return "Error: Debes seleccionar al menos un tipo de carácter."
    if longitud < len(grupos):
        return "Error: La longitud debe ser al menos igual a la cantidad de tipos seleccionados."

    caracteres = ''.join(grupos)
    contrasena = [secrets.choice(grupo) for grupo in grupos]
    contrasena.extend(secrets.choice(caracteres) for _ in range(longitud - len(grupos)))
    secrets.SystemRandom().shuffle(contrasena)

    return ''.join(contrasena)


def calcular_entropia(contra):
    longitud = len(contra)
    conjunto = 0

    if any(c.islower() for c in contra):
        conjunto += 26
    if any(c.isupper() for c in contra):
        conjunto += 26
    if any(c.isdigit() for c in contra):
        conjunto += 10
    if any(c in string.punctuation for c in contra):
        conjunto += len(string.punctuation)

    if conjunto > 0:
        entropia = longitud * math.log2(conjunto)
    else:
        entropia = 0

    return entropia


def clasificar_seguridad(entropia):
    if entropia < 40:
        return "❌ MUY INSEGURA"
    elif entropia < 60:
        return "⚠️ DÉBIL"
    elif entropia < 80:
        return "✅ ACEPTABLE"
    else:
        return "🔒 MUY SEGURA"


def verificar_contrasena_pwned(contrasena):
    """Verificar si una contraseña ha sido comprometida en Have I Been Pwned."""
    sha1_hash = hashlib.sha1(contrasena.encode('utf-8')).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    try:
        # Hacemos una solicitud GET a la API de Have I Been Pwned
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url, timeout=10)
    except requests.Timeout:
        return "⚠️ Tiempo de espera agotado al consultar Have I Been Pwned."
    except requests.RequestException:
        return "⚠️ No se pudo conectar con Have I Been Pwned."

    if response.status_code == 200:
        # Analizar las respuestas de la API para ver si nuestra contraseña está comprometida
        hashes = response.text.splitlines()
        for hash_entry in hashes:
            hash_suffix, count = hash_entry.split(':')
            if hash_suffix == suffix:
                return f"⚠️ ¡Comprometida! Esta contraseña ha sido filtrada {count} veces."
        return "✅ La contraseña no ha sido comprometida."
    else:
        return "⚠️ Error al consultar la API de Have I Been Pwned."


def verificar_contrasena():
    try:
        contrasena = input("🔒 Ingresa la contraseña para verificar su seguridad: ")
        entropia = calcular_entropia(contrasena)
        seguridad = clasificar_seguridad(entropia)

        print(f"\n🔑 Contraseña ingresada: {contrasena}")
        print(f"   🔒 Seguridad: {seguridad}")
        print(f"   📊 Entropía estimada: {entropia:.2f} bits")
        print("   ℹ️ Esta cifra es una estimación basada en los tipos de caracteres detectados.")
        print("   🌐 Estado en internet: Usa la opción 3 para consultar Have I Been Pwned.\n")

    except ValueError:
        print("⚠️ Error: Ingresa una contraseña válida.")


def generar_y_mostrar_contrasenas():
    try:
        print("\n🛠️  **CONFIGURACIÓN DE CONTRASEÑAS** 🛠️")
        longitud = int(input("🔢 Longitud de la contraseña: "))
        usar_mayus = input("🔠 ¿Incluir mayúsculas? (s/n): ").lower() == 's'
        usar_minus = input("🔡 ¿Incluir minúsculas? (s/n): ").lower() == 's'
        usar_numeros = input("🔢 ¿Incluir números? (s/n): ").lower() == 's'
        usar_simbolos = input("🔣 ¿Incluir símbolos? (s/n): ").lower() == 's'

        if longitud <= 0:
            print("⚠️ Error: La longitud debe ser mayor que cero.")
            return
        if not any([usar_mayus, usar_minus, usar_numeros, usar_simbolos]):
            print("⚠️ Error: Debes seleccionar al menos un tipo de carácter.")
            return
        if longitud < sum([usar_mayus, usar_minus, usar_numeros, usar_simbolos]):
            print("⚠️ Error: La longitud debe cubrir todos los tipos de caracteres seleccionados.")
            return

        contraseñas = []

        for _ in range(5):
            contrasena = generar_contrasena(longitud, usar_mayus, usar_minus, usar_numeros, usar_simbolos)
            if contrasena.startswith("Error:"):
                print(f"⚠️ {contrasena}")
                return
            entropia = calcular_entropia(contrasena)
            contraseñas.append((contrasena, entropia, clasificar_seguridad(entropia)))

        print("\n🎯 **CONTRASEÑAS GENERADAS** 🎯\n")

        for i, (contrasena, entropia, seguridad) in enumerate(contraseñas, 1):
            print(f"🔹 Contraseña #{i}: {contrasena}")
            print(f"   🔑 Seguridad: {seguridad}")
            print(f"   📊 Entropía estimada: {entropia:.2f} bits\n")

        print("ℹ️ La entropía mostrada es una estimación y no se usa para declarar una contraseña como la mejor o la peor.\n")

    except ValueError:
        print("⚠️ Error: Ingresa valores numéricos válidos.")


def menu():
    while True:
        print("\n🔐 **MENÚ DE OPCIONES** 🔐")
        print("1️⃣  Generar contraseñas seguras")
        print("2️⃣  Verificar seguridad local de una contraseña")
        print("3️⃣  Consultar contraseña en Have I Been Pwned (internet)")
        print("4️⃣  Salir")

        opcion = input("\n📌 Elige una opción: ")

        if opcion == "1":
            generar_y_mostrar_contrasenas()
        elif opcion == "2":
            verificar_contrasena()
        elif opcion == "3":
            contrasena = input("🔒 Ingresa la contraseña para verificar si ha sido comprometida: ")
            pwned_status = verificar_contrasena_pwned(contrasena)
            print(f"\n🌐 Estado de la contraseña: {pwned_status}")
        elif opcion == "4":
            print("👋 ¡Hasta luego! Usa contraseñas seguras.")
            break
        else:
            print("⚠️ Opción no válida. Inténtalo de nuevo.")


if __name__ == "__main__":
    menu()
