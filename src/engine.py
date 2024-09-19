import requests
import json
import re

# Configura las credenciales y URL de la API
url_base = 'https://api.xdr.trendmicro.com'
url_path = '/v3.0/response/suspiciousObjects'
url_path_ioc_delete = '/v3.0/response/suspiciousObjects/delete'
url_path_isolate = '/v3.0/response/endpoints/isolate'
url_path_restore = '/v3.0/response/endpoints/restore'
url_path_malware_scan = '/v3.0/response/endpoints/startMalwareScan'
url_path_custom_script = '/v3.0/response/customScripts'
url_path_run_script = '/v3.0/response/endpoints/runScript'
url_path_disable_account = '/v3.0/response/domainAccounts/disable'
url_path_enable_account = '/v3.0/response/domainAccounts/enable'
url_path_logout_account = '/v3.0/response/domainAccounts/signOut'
url_path_reset_account_password = '/v3.0/response/domainAccounts/resetPassword'
url_path_delete_email = '/v3.0/response/emails/delete'
url_path_quarantine_email = '/v3.0/response/emails/quarantine'
url_path_restore_email = '/v3.0/response/emails/restore'
url_path_email_activities = '/v3.0/search/emailActivities'
token = 'TOKEN' # Sustituye con tu token real

headers = {
    'Authorization': 'Bearer ' + token,
    'Content-Type': 'application/json;charset=utf-8'
}

def get_chiste():
    joke = requests.get('https://api.chucknorris.io/jokes/random')
    data = joke.json()
    return data["value"]

def get_ips(content):
    # FunciÃƒÆ’Ã‚Â³n simplificada para extraer IPs
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    return re.findall(ip_pattern, content)

def get_hashes(content):
    # FunciÃƒÆ’Ã‚Â³n simplificada para extraer hashes SHA-256
    hash_pattern = r'\b[A-Fa-f0-9]{64}\b'
    return re.findall(hash_pattern, content)

def upload_iocs(hashes):
    iocs = [{'fileSha256': h, 'description': 'HASH TelegramBot', 'scanAction': 'log', 'riskLevel': 'low', 'daysToExpiration': '30'} for h in hashes]
    response = requests.post(url_base + url_path, headers=headers, json=iocs)
    if response.status_code == 200:
        print("Data uploaded successfully.")
        return json.dumps(response.json(), indent=4)
    else:
        print(f"Failed to upload data. Status code: {response.status_code}")
        return response.text

def get_endpoints(content):
    # FunciÃƒÆ’Ã‚Â³n simplificada para extraer nombres de endpoints (simulando la funcionalidad)
    # Ajusta esta funciÃƒÆ’Ã‚Â³n segÃƒÆ’Ã‚Âºn tus necesidades
    return content.splitlines()

def isolate_endpoints(endpoints):
    isolate = [{'endpointName': e, 'description': 'Aislado TelegramBot'} for e in endpoints]
    response = requests.post(url_base + url_path_isolate, headers=headers, json=isolate)
    if response.status_code == 207:
        data = response.json()
        if data[0]['status'] == 202:
            return ("Tarea de aislamiento ejecutada correctamente")
        else:
            return (response.text)
    # Busca el status 202 en el cuerpo de la respuesta
    else:
        print(f"Equipo no aislado. Status code: {response.status_code}")
        '''return response.text'''
        return ("equipo no aislado")

def restore_endpoints(lista_equipos):
    body = []
    for equipo in lista_equipos:
        body.append({
            'description': f'Restore {equipo}',
            'endpointName': equipo
        })
    # Realizar la solicitud HTTP POST
    r = requests.post(url_base + url_path_restore, headers=headers, json=body)
    # Manejar la respuesta
    if r.status_code == 207:
        data = r.json()
        if data[0]['status'] == 202:
            return ("Tarea de restauracion ejecutada correctamente")
        else:
            return (r.text)
    else:
        return f'Error: {r.status_code} - {r.text}'

def start_malware_scan(lista_equipos):
 # Construir el cuerpo de la solicitud
    body = {
        'endpoints': []
    }
    for equipo in lista_equipos:
        body['endpoints'].append({
            'description': f'Malware scan for {equipo}',
            'endpointName': equipo
        })
    # Realizar la solicitud HTTP POST
    r = requests.post(url_base + url_path_malware_scan, headers=headers, json=body)
    # Manejar la respuesta
    if r.status_code == 200:
        if 'application/json' in r.headers.get('Content-Type', ''):
            return r.json()
        else:
            return r.text
    else:
        return f'Error: {r.status_code} - {r.text}'

def procesar_sha256(hashes: list) -> str:
    # Filtrar hashes vÃƒÂ¡lidos (de 64 caracteres)
    valid_hashes = [h for h in hashes if len(h) == 64]
    
    # Si no hay hashes vÃƒÂ¡lidos, devuelve un mensaje de error
    if not valid_hashes:
        return json.dumps({"error": "No se proporcionaron hashes SHA256 validos."}, indent=2)

    # Construye el cuerpo de la solicitud
    body = [
        {
            'description': f'SHA256 hash {i+1}',
            'fileSha256': hash_value
        }
        for i, hash_value in enumerate(valid_hashes)
    ]

    # Enviar la solicitud POST a la API
    try:
        r = requests.post(url_base + url_path, headers=headers, json=body)
        r.raise_for_status()  # Lanza un error si la respuesta tiene un cÃƒÂ³digo de estado 4xx/5xx

        if r.status_code == 207:
            data = r.json()
            # Suponiendo que la respuesta de la API contiene informaciÃƒÂ³n sobre cada hash
            # y que cada hash tiene un campo 'status' para verificar el ÃƒÂ©xito.
            successful_count = sum(1 for item in data if item.get('status') == 202)
            
            response_json = {
                "message": "IOCs cargados correctamente",
                "Cantidad de IOCs cargados": successful_count,
                "response_data": data
            }
            return json.dumps(response_json, indent=2)
        else:
            return json.dumps({
                "error": "Error al cargar hashes",
                "status_code": r.status_code
            }, indent=2)
    except requests.exceptions.RequestException as e:
        return json.dumps({
            "error": "Error al conectar con la API",
            "details": str(e)
        }, indent=2)
        
def procesar_sha1(hashes: list) -> str:
    # Filtrar hashes vÃƒÂ¡lidos (de 64 caracteres)
    valid_hashes = [h for h in hashes if len(h) == 40]
    
    # Si no hay hashes vÃƒÂ¡lidos, devuelve un mensaje de error
    if not valid_hashes:
        return json.dumps({"error": "No se proporcionaron hashes SHA1 validos."}, indent=2)

    # Construye el cuerpo de la solicitud
    body = [
        {
            'description': f'SHA hash {i+1}',
            'fileSha1': hash_value
        }
        for i, hash_value in enumerate(valid_hashes)
    ]

    # Enviar la solicitud POST a la API
    try:
        r = requests.post(url_base + url_path, headers=headers, json=body)
        r.raise_for_status()  # Lanza un error si la respuesta tiene un cÃƒÂ³digo de estado 4xx/5xx

        if r.status_code == 207:
            data = r.json()
            # Suponiendo que la respuesta de la API contiene informaciÃƒÂ³n sobre cada hash
            # y que cada hash tiene un campo 'status' para verificar el ÃƒÂ©xito.
            successful_count = sum(1 for item in data if item.get('status') == 202)
            
            response_json = {
                "message": "IOCs cargados correctamente",
                "Cantidad de IOCs cargados": successful_count,
                "response_data": data
            }
            return json.dumps(response_json, indent=2)
        else:
            return json.dumps({
                "error": "Error al cargar hashes",
                "status_code": r.status_code
            }, indent=2)
    except requests.exceptions.RequestException as e:
        return json.dumps({
            "error": "Error al conectar con la API",
            "details": str(e)
        }, indent=2)

def procesar_ip(ips: list) -> str:
    # Construye el cuerpo de la solicitud
    body = [
        {
            'description': f'IP {i+1}',
            'ip': ip_value
        }
        for i, ip_value in enumerate(ips)
    ]

    # Enviar la solicitud POST a la API
    try:
        r = requests.post(url_base + url_path, headers=headers, json=body)
        r.raise_for_status()  # Lanza un error si la respuesta tiene un cÃƒÂ³digo de estado 4xx/5xx

        if r.status_code == 207:
            data = r.json()
            # Suponiendo que la respuesta de la API contiene informaciÃƒÂ³n sobre cada hash
            # y que cada hash tiene un campo 'status' para verificar el ÃƒÂ©xito.
            successful_count = sum(1 for item in data if item.get('status') == 202)
            
            response_json = {
                "message": "IOCs cargados correctamente",
                "Cantidad de IOCs cargados": successful_count,
                "response_data": data
            }
            return json.dumps(response_json, indent=2)
        else:
            return json.dumps({
                "error": "Error al cargar IP",
                "status_code": r.status_code
            }, indent=2)
    except requests.exceptions.RequestException as e:
        return json.dumps({
            "error": "Error al conectar con la API",
            "details": str(e)
        }, indent=2)

def procesar_url(urls: list) -> str:
    # Construye el cuerpo de la solicitud
    body = [
        {
            'description': f'URL {i+1}',
            'url': url_value
        }
        for i, url_value in enumerate(urls)
    ]

    # Enviar la solicitud POST a la API
    try:
        r = requests.post(url_base + url_path, headers=headers, json=body)
        r.raise_for_status()  # Lanza un error si la respuesta tiene un cÃƒÂ³digo de estado 4xx/5xx

        if r.status_code == 207:
            data = r.json()
            # Suponiendo que la respuesta de la API contiene informaciÃƒÂ³n sobre cada hash
            # y que cada hash tiene un campo 'status' para verificar el ÃƒÂ©xito.
            successful_count = sum(1 for item in data if item.get('status') == 202)
            
            response_json = {
                "message": "IOCs cargados correctamente",
                "Cantidad de IOCs cargados": successful_count,
                "response_data": data
            }
            return json.dumps(response_json, indent=2)
        else:
            return json.dumps({
                "error": "Error al cargar URL",
                "status_code": r.status_code
            }, indent=2)
    except requests.exceptions.RequestException as e:
        return json.dumps({
            "error": "Error al conectar con la API",
            "details": str(e)
        }, indent=2)

def procesar_domain(domains: list) -> str:
    # Construye el cuerpo de la solicitud
    body = [
        {
            'description': f'Dominio {i+1}',
            'domain': domain_value
        }
        for i, domain_value in enumerate(domains)
    ]
    
    # Enviar la solicitud POST a la API
    try:
        r = requests.post(url_base + url_path, headers=headers, json=body)
        r.raise_for_status()  # Lanza un error si la respuesta tiene un cÃƒÂ³digo de estado 4xx/5xx

        if r.status_code == 207:
            data = r.json()
            # Suponiendo que la respuesta de la API contiene informaciÃƒÂ³n sobre cada hash
            # y que cada hash tiene un campo 'status' para verificar el ÃƒÂ©xito.
            successful_count = sum(1 for item in data if item.get('status') == 202)
            
            response_json = {
                "message": "IOCs cargados correctamente",
                "Cantidad de IOCs cargados": successful_count,
                "response_data": data
            }
            return json.dumps(response_json, indent=2)
        else:
            return json.dumps({
                "error": "Error al cargar dominio",
                "status_code": r.status_code
            }, indent=2)
    except requests.exceptions.RequestException as e:
        return json.dumps({
            "error": "Error al conectar con la API",
            "details": str(e)
        }, indent=2)

def procesar_sender(senders: list) -> str:
    # Construye el cuerpo de la solicitud
    body = [
        {
            'description': f'Remitente {i+1}',
            'senderMailAddress': sender_value
        }
        for i, sender_value in enumerate(senders)
    ]
    
    # Enviar la solicitud POST a la API
    try:
        r = requests.post(url_base + url_path, headers=headers, json=body)
        r.raise_for_status()  # Lanza un error si la respuesta tiene un cÃƒÂ³digo de estado 4xx/5xx

        if r.status_code == 207:
            data = r.json()
            # Suponiendo que la respuesta de la API contiene informaciÃƒÂ³n sobre cada hash
            # y que cada hash tiene un campo 'status' para verificar el ÃƒÂ©xito.
            successful_count = sum(1 for item in data if item.get('status') == 202)
            
            response_json = {
                "message": "IOCs cargados correctamente",
                "Cantidad de IOCs cargados": successful_count,
                "response_data": data
            }
            return json.dumps(response_json, indent=2)
        else:
            return json.dumps({
                "error": "Error al cargar sender",
                "status_code": r.status_code
            }, indent=2)
    except requests.exceptions.RequestException as e:
        return json.dumps({
            "error": "Error al conectar con la API",
            "details": str(e)
        }, indent=2)


def eliminar_suspicious_objects_sha256(lista_sha256):
    # Validar que la lista no estÃƒÆ’Ã‚Â© vacÃƒÆ’Ã‚Â­a
    if not lista_sha256:
        return "No se proporcionaron hashes SHA256 para eliminar."

    # Construir el cuerpo de la solicitud
    body = []
    for sha256 in lista_sha256:
        # AÃƒÆ’Ã‚Â±adir hashes SHA256 sospechosos al cuerpo
        body.append({
            'description': f'Eliminando {sha256}',
            'fileSha256': sha256  # EspecÃƒÆ’Ã‚Â­fico para hashes SHA256 sospechosos
        })

    # Realizar la solicitud HTTP POST con manejo de excepciones
    try:
        r = requests.post(url_base + url_path_ioc_delete, headers=headers, json=body)

        # Manejar la respuesta
        if r.status_code == 200:
            if 'application/json' in r.headers.get('Content-Type', ''):
                return r.json()
            else:
                return r.text
        else:
            return f'Error: {r.status_code} - {r.text}'
    except requests.exceptions.RequestException as e:
        return f'Error al hacer la solicitud: {e}'

def eliminar_suspicious_objects_sha1(lista_sha1):
    # Validar que la lista no estÃƒÆ’Ã‚Â© vacÃƒÆ’Ã‚Â­a
    if not lista_sha1:
        return "No se proporcionaron hashes SHA1 para eliminar."

    # Construir el cuerpo de la solicitud
    body = []
    for sha1 in lista_sha1:
        # AÃƒÆ’Ã‚Â±adir hashes SHA1 sospechosos al cuerpo
        body.append({
            'description': f'Eliminando {sha1}',
            'fileSha1': sha1  # EspecÃƒÆ’Ã‚Â­fico para hashes SHA1 sospechosos
        })

    # Realizar la solicitud HTTP POST con manejo de excepciones
    try:
        r = requests.post(url_base + url_path_ioc_delete, headers=headers, json=body)

        # Manejar la respuesta
        if r.status_code == 200:
            if 'application/json' in r.headers.get('Content-Type', ''):
               return r.json()
            else:
                return r.text
        else:
            return f'Error: {r.status_code} - {r.text}'
    except requests.exceptions.RequestException as e:
        return f'Error al hacer la solicitud: {e}'

def eliminar_suspicious_objects_ip(lista_ips):
    # Validar que la lista no estÃƒÆ’Ã‚Â© vacÃƒÆ’Ã‚Â­a
    if not lista_ips:
        return "No se proporcionaron IPs para eliminar."

    # Construir el cuerpo de la solicitud
    body = []
    for ip in lista_ips:
        # AÃƒÆ’Ã‚Â±adir IPs sospechosas al cuerpo
        body.append({
            'description': f'Eliminando {ip}',
            'ip': ip  # EspecÃƒÆ’Ã‚Â­fico para IPs sospechosas
        })

    # Realizar la solicitud HTTP POST con manejo de excepciones
    try:
        r = requests.post(url_base + url_path_ioc_delete, headers=headers, json=body)

        # Manejar la respuesta
        if r.status_code == 200:
            if 'application/json' in r.headers.get('Content-Type', ''):
                return r.json()
            else:
                return r.text
        else:
            return f'Error: {r.status_code} - {r.text}'
    except requests.exceptions.RequestException as e:
        return f'Error al hacer la solicitud: {e}'

def eliminar_suspicious_objects_url(lista_urls):
    # Validar que la lista no estÃƒÆ’Ã‚Â© vacÃƒÆ’Ã‚Â­a
    if not lista_urls:
        return "No se proporcionaron URLs para eliminar."

    # Construir el cuerpo de la solicitud
    body = []
    for url in lista_urls:
        # AÃƒÆ’Ã‚Â±adir objetos sospechosos al cuerpo
        body.append({
            'description': f'Eliminando {url}',
            'url': url  # EspecÃƒÆ’Ã‚Â­fico para URLs sospechosas
        })

    # Realizar la solicitud HTTP POST con manejo de excepciones
    try:
        r = requests.post(url_base + url_path_ioc_delete, headers=headers, json=body)

        # Manejar la respuesta
        if r.status_code == 200:
            if 'application/json' in r.headers.get('Content-Type', ''):
                return r.json()
            else:
                return r.text
        else:
            return f'Error: {r.status_code} - {r.text}'
    except requests.exceptions.RequestException as e:
        return f'Error al hacer la solicitud: {e}'

def eliminar_suspicious_objects_domain(lista_dominios):
    # Validar que la lista no estÃƒÆ’Ã‚Â© vacÃƒÆ’Ã‚Â­a
    if not lista_dominios:
        return "No se proporcionaron dominios para eliminar."

    # Construir el cuerpo de la solicitud
    body = []
    for dominio in lista_dominios:
        # AÃƒÆ’Ã‚Â±adir dominios sospechosos al cuerpo
        body.append({
            'description': f'Eliminando {dominio}',
            'domain': dominio  # EspecÃƒÆ’Ã‚Â­fico para dominios sospechosos
        })

    # Realizar la solicitud HTTP POST con manejo de excepciones
    try:
        r = requests.post(url_base + url_path_ioc_delete, headers=headers, json=body)

        # Manejar la respuesta
        if r.status_code == 200:
            if 'application/json' in r.headers.get('Content-Type', ''):
                return r.json()
            else:
                return r.text
        else:
            return f'Error: {r.status_code} - {r.text}'
    except requests.exceptions.RequestException as e:
        return f'Error al hacer la solicitud: {e}'

def eliminar_suspicious_objects_sender(lista_objetos):
    # Validar que la lista no estÃƒÆ’Ã‚Â© vacÃƒÆ’Ã‚Â­a
    if not lista_objetos:
        return "No se proporcionaron objetos para eliminar."

    # Construir el cuerpo de la solicitud
    body = []
    for objeto in lista_objetos:
        # AÃƒÆ’Ã‚Â±adir objetos sospechosos al cuerpo
        body.append({
            'description': f'Eliminando {objeto}',
            'senderMailAddress': objeto  # EspecÃƒÆ’Ã‚Â­fico para remitentes sospechosos
        })

    # Realizar la solicitud HTTP POST con manejo de excepciones
    try:
        r = requests.post(url_base + url_path_ioc_delete, headers=headers, json=body)

        # Manejar la respuesta
        if r.status_code == 200:
            if 'application/json' in r.headers.get('Content-Type', ''):
                return r.json()
            else:
                return r.text
        else:
            return f'Error: {r.status_code} - {r.text}'
    except requests.exceptions.RequestException as e:
        return f'Error al hacer la solicitud: {e}'

# Listar Script personalizadas:

def listar_scripts_personalizados():
    # Configurar encabezados (asumiendo que ya tienes el token en headers como variable global)
    try:
        # Realizar la solicitud HTTP GET
        r = requests.get(url_base + url_path_custom_script, headers=headers)

        # Manejar la respuesta
        if r.status_code == 200:
            if 'application/json' in r.headers.get('Content-Type', ''):
                return r.json()
            else:
                return r.text
        else:
            return f'Error: {r.status_code} - {r.text}'
    except requests.exceptions.RequestException as e:
        return f'Error al hacer la solicitud: {e}'

def ejecutar_script_customizado(nombre_script, lista_endpoints, parametros=None):
    # Construir el cuerpo de la solicitud
    body = []
    for endpoint in lista_endpoints:
        # Construir el diccionario de cada endpoint
        script_info = {
            'description': f'Ejecutando script {nombre_script} en {endpoint}',
            'endpointName': endpoint,
            'fileName': nombre_script  # Nombre del script a ejecutar
        }

        # Agregar los parÃƒÆ’Ã‚Â¡metros si estÃƒÆ’Ã‚Â¡n presentes
        if parametros:
            script_info['parameter'] = ' '.join(parametros)

        body.append(script_info)

    # Realizar la solicitud HTTP POST con manejo de excepciones
    try:
        r = requests.post(url_base + url_path_run_script, headers=headers, json=body)

        # Manejar la respuesta
        if r.status_code == 200:
            if 'application/json' in r.headers.get('Content-Type', ''):
                return r.json()
            else:
                return r.text
        else:
            return f'Error: {r.status_code} - {r.text}'

    except requests.exceptions.RequestException as e:
        return f'Error al hacer la solicitud: {e}'

#Funcion para deshabilitar cuentas

def deshabilitar_cuentas(lista_cuentas):
    # Validar que la lista no estÃƒÆ’Ã‚Â© vacÃƒÆ’Ã‚Â­a
    if not lista_cuentas:
        return "No se proporcionaron cuentas para deshabilitar."
    # Construir el cuerpo de la solicitud
    body = []
    for cuenta in lista_cuentas:
        body.append({
            'accountName': cuenta,
            'description': f'Deshabilitando cuenta {cuenta}'
        })
    # Realizar la solicitud HTTP POST con manejo de excepciones
    try:
        r = requests.post(url_base + url_path_disable_account, headers=headers, json=body)
        # Manejar la respuesta
        if r.status_code == 200:
            if 'application/json' in r.headers.get('Content-Type', ''):
                return r.json()
            else:
                return r.text
        else:
            return f'Error: {r.status_code} - {r.text}'
    except requests.exceptions.RequestException as e:
        return f'Error al hacer la solicitud: {e}'

#Funcion para habilitar cuentas deshabilitadas

def habilitar_cuentas(lista_cuentas):
    # Validar que la lista no estÃƒÆ’Ã‚Â© vacÃƒÆ’Ã‚Â­a
    if not lista_cuentas:
        return "No se proporcionaron cuentas para habilitar."
    # Construir el cuerpo de la solicitud
    body = []
    for cuenta in lista_cuentas:
        body.append({
            'accountName': cuenta,
            'description': f'Habilitando cuenta {cuenta}'
        })
    # Realizar la solicitud HTTP POST con manejo de excepciones
    try:
        r = requests.post(url_base + url_path_enable_account, headers=headers, json=body)
        # Manejar la respuesta
        if r.status_code == 200:
            if 'application/json' in r.headers.get('Content-Type', ''):
                return r.json()
            else:
                return r.text
        else:
            return f'Error: {r.status_code} - {r.text}'
    except requests.exceptions.RequestException as e:
        return f'Error al hacer la solicitud: {e}'

#Funcion para forzar deslogueo de cuentas

def desloguear_cuentas(lista_cuentas):
    # Validar que la lista no estÃƒÆ’Ã‚Â© vacÃƒÆ’Ã‚Â­a
    if not lista_cuentas:
        return "No se proporcionaron cuentas para desloguear."
    # Construir el cuerpo de la solicitud
    body = []
    for cuenta in lista_cuentas:
        body.append({
            'accountName': cuenta,
            'description': f'Deslogueando cuenta {cuenta}'
        })
    # Realizar la solicitud HTTP POST con manejo de excepciones
    try:
        r = requests.post(url_base + url_path_logout_account, headers=headers, json=body)
        # Manejar la respuesta
        if r.status_code == 200:
            if 'application/json' in r.headers.get('Content-Type', ''):
                return r.json()
            else:
                return r.text
        else:
            return f'Error: {r.status_code} - {r.text}'
    except requests.exceptions.RequestException as e:
        return f'Error al hacer la solicitud: {e}'

#Funcion para resetear el password de la cuenta

def resetear_password(lista_cuentas):
    # Validar que la lista no estÃƒÆ’Ã‚Â© vacÃƒÆ’Ã‚Â­a
    if not lista_cuentas:
        return "No se proporcionaron cuentas para restablecer las contraseÃƒÆ’Ã‚Â±as."
    # Construir el cuerpo de la solicitud
    body = []
    for cuenta in lista_cuentas:
        body.append({
            'accountName': cuenta,
            'description': f'Reseteando contraseÃƒÆ’Ã‚Â±a de la cuenta {cuenta}'
        })
    # Realizar la solicitud HTTP POST con manejo de excepciones
    try:
        r = requests.post(url_base + url_path_reset_account_password, headers=headers, json=body)

        # Manejar la respuesta
        if r.status_code == 200:
            if 'application/json' in r.headers.get('Content-Type', ''):
                return r.json()
            else:
                return r.text
        else:
            return f'Error: {r.status_code} - {r.text}'
    except requests.exceptions.RequestException as e:
        return f'Error al hacer la solicitud: {e}'

#Funciones referentes a correo


def eliminar_mensajes_por_uuid(uuids: list) -> str:
    # Construir el cuerpo de la solicitud
    body = [
        {
            'description': f'Eliminando mensaje {i+1}',
            'uniqueId': uuid_value
        }
        for i, uuid_value in enumerate(uuids)
    ]

    # EnvÃƒÆ’Ã‚Â­a la solicitud POST a la API
    try:
        r = requests.post(url_base + url_path_delete_email, headers=headers, json=body)
        if r.status_code == 200:
            return "Mensajes eliminados correctamente."
        else:
            return f"Error al eliminar mensajes. CÃƒÆ’Ã‚Â³digo de estado: {r.status_code}"
    except Exception as e:
        return f"Error al conectar con la API: {e}"

def mandar_mensajes_a_cuarentena(uuids: list) -> str:
    # Construir el cuerpo de la solicitud
    body = [
        {
            'description': f'Enviando mensaje {i+1} a cuarentena',
            'uniqueId': uuid_value
        }
        for i, uuid_value in enumerate(uuids)
    ]

    # EnvÃƒÆ’Ã‚Â­a la solicitud POST a la API
    try:
        r = requests.post(url_base + url_path_quarantine_email, headers=headers, json=body)
        if r.status_code == 200:
            return "Mensajes enviados a cuarentena correctamente."
        else:
            return f"Error al enviar mensajes a cuarentena. CÃƒÆ’Ã‚Â³digo de estado: {r.status_code}"
    except Exception as e:
        return f"Error al conectar con la API: {e}"

def restaurar_mensajes(uuids: list) -> str:
    # Construir el cuerpo de la solicitud
    body = [
        {
            'description': f'Restaurando mensaje {i+1}',
            'uniqueId': uuid_value
        }
        for i, uuid_value in enumerate(uuids)
    ]

    # EnvÃƒÆ’Ã‚Â­a la solicitud POST a la API
    try:
        r = requests.post(url_base + url_path_restore_email, headers=headers, json=body)
        if r.status_code == 200:
            return "Mensajes restaurados correctamente."
        else:
            return f"Error al restaurar mensajes. CÃƒÆ’Ã‚Â³digo de estado: {r.status_code}"
    except Exception as e:
        return f"Error al conectar con la API: {e}"

def buscar_correos_por_asunto(asunto: str) -> dict:
    headersCorreo = {
        'Authorization': 'Bearer ' + token, # AsegÃƒÆ’Ã‚Âºrate de reemplazar 'YOUR_TOKEN' por el token correcto
        'Content-Type': 'application/json;charset=utf-8',
        'TMV1-Query': f'mailMsgSubject:{asunto}'  # Asunto ya viene con comillas
    }
    try:
        # Realiza la solicitud GET a la API
        r = requests.get(url_base + url_path_email_activities, headers=headersCorreo)

        # Verifica si la solicitud fue exitosa
        if r.status_code == 200:
            return r.json()
        else:
            return {'error': f"CÃƒÆ’Ã‚Â³digo de estado: {r.status_code}"}
    except requests.exceptions.RequestException as e:
        return {'error': str(e)}



