import os
import socket
import logging
import threading
import requests
from scapy.all import ARP, Ether, srp, IP, ICMP, sr1
from ipaddress import ip_network

# Configuración de logging
logging.basicConfig(filename="network_scan.log", level=logging.INFO)


from scapy.all import ARP, Ether, srp

def get_local_ip():
    # Obtener la dirección IP local (de la interfaz de red activa)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(("8.8.8.8", 80))  # Conectarse a un servidor externo para determinar la IP local
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'  # En caso de no encontrar la red activa
    finally:
        s.close()
    
    return local_ip



# Función 1: Escanear dispositivos en la red
def scan_network(target_ip):
    print(f"Escaneando la red {target_ip}...")
    arp_request = ARP(pdst=target_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=10, verbose=False)[0]

    devices = []
    for element in answered_list:
        device_info = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        devices.append(device_info)
        log_device_info(device_info)  # Log de dispositivos encontrados
    
    print("\nDispositivos conectados en la red:")
    for device in devices:
        print(f"IP: {device['ip']} | MAC: {device['mac']}")
    
    return devices

# Función 2: Escanear puertos abiertos
def scan_ports(ip, ports):
    open_ports = []
    print(f"Escaneando puertos en {ip}...")
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)  # Aumentar el timeout a 3 segundos
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
            scan_service(ip, port)  # Escaneo de servicios
        sock.close()

    print("\nPuertos abiertos:")
    if open_ports:
        for port in open_ports:
            print(f"Puerto {port} abierto")
        log_open_ports(ip, open_ports)  # Log de puertos abiertos
    else:
        print("No se encontraron puertos abiertos.")
    
    return open_ports

# Función 3: Comprobar y mostrar los servicios disponibles en los puertos
def scan_service(ip, port):
    try:
        if port == 80:  # HTTP
            response = requests.get(f"http://{ip}:{port}")
            print(f"Servicio HTTP detectado en {ip}:{port} - Servidor: {response.headers.get('Server')}")
        elif port == 443:  # HTTPS
            response = requests.get(f"https://{ip}:{port}")
            print(f"Servicio HTTPS detectado en {ip}:{port} - Servidor: {response.headers.get('Server')}")
    except requests.exceptions.RequestException as e:
        print(f"No se pudo conectar a {ip}:{port} - Error: {str(e)}")

# Función 4: Escaneo de vulnerabilidades básicas (ejemplo para SSH)
def check_for_vulnerabilities(ip, port):
    if port == 22:  # Puerto SSH
        print(f"Comprobando vulnerabilidades de SSH en {ip}:{port}...")
        # Aquí puedes añadir lógica para comprobar vulnerabilidades conocidas en el servicio SSH.
        # Ejemplo: Verificar la versión de OpenSSH si tienes acceso al servicio.

# Función 5: Escaneo de red por rango de IP
def scan_range(network_range):
    net = ip_network(network_range)
    for ip in net.hosts():
        scan_network(str(ip))

# Función 6: Detectar firewalls o IDS (detección básica)
def detect_firewall(ip):
    response = sr1(IP(dst=ip)/ICMP(), timeout=1, verbose=False)
    if response is None:
        print(f"Firewall detectado en {ip}")

# Función 7: Generación de informe HTML
def generate_html_report(devices, open_ports):
    html = "<html><body><h1>Reporte de Escaneo de Red</h1><h2>Dispositivos Encontrados</h2><ul>"
    for device in devices:
        html += f"<li>{device['ip']} | {device['mac']}</li>"
    html += "</ul><h2>Puertos Abiertos</h2><ul>"
    for port in open_ports:
        html += f"<li>Puerto {port} abierto</li>"
    html += "</ul></body></html>"
    with open("scan_report.html", "w") as file:
        file.write(html)

# Función 8: Verificación de dispositivos por sistema operativo
def detect_os(ip):
    pkt = IP(dst=ip)/TCP(dport=80, flags="S")
    response = sr1(pkt, timeout=1, verbose=False)
    if response:
        if response.haslayer(TCP) and response[TCP].flags == 18:
            print(f"Posible sistema operativo: {ip} - Windows")
        else:
            print(f"Posible sistema operativo: {ip} - Linux")

# Función 9: Escaneo multihilo (concurrencia) de puertos
def scan_ports_concurrent(ip, start_port, end_port):
    open_ports = []
    threads = []
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_single_port, args=(ip, port, open_ports))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    return open_ports

def scan_single_port(ip, port, open_ports):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((ip, port))
    if result == 0:
        open_ports.append(port)
    sock.close()

# Función para log de dispositivos encontrados
def log_device_info(device):
    logging.info(f"Dispositivo encontrado - IP: {device['ip']} | MAC: {device['mac']}")

# Función para log de puertos abiertos
def log_open_ports(ip, open_ports):
    logging.info(f"Puertos abiertos en {ip}: {', '.join(map(str, open_ports))}")

# Función principal
def network_info(target_ip):
    devices = scan_network(target_ip)
    open_ports = []
    for device in devices:
        open_ports_device = scan_ports(device['ip'], [22, 80, 443])  # Escanea los puertos más comunes (SSH, HTTP, HTTPS)
        open_ports.extend(open_ports_device)
        detect_os(device['ip'])
        detect_firewall(device['ip'])
        check_for_vulnerabilities(device['ip'], 22)
    
    # Generar el informe HTML
    generate_html_report(devices, open_ports)

# Menú principal
def menu():
    print("Seleccione una opción:")
    print("1. Escanear dispositivos en la red")
    print("2. Escanear puertos abiertos de un dispositivo")
    print("3. Comprobar vulnerabilidades")
    print("4. Escanear rango de IPs")
    print("5. Detectar firewalls")
    print("6. Generar reporte HTML")
    print("7. Salir")

    option = input("Ingrese el número de la opción: ")

    if option == "1":
        target_ip = get_local_ip() + "/24"
        scan_network(target_ip)
    elif option == "2":
        ip = get_local_ip()
        ports = input("Ingrese los puertos a escanear (separados por coma): ").split(",")
        ports = [int(port) for port in ports]
        scan_ports(ip, ports)
    elif option == "3":
        ip = get_local_ip()
        port = int(input("Ingrese el puerto a comprobar: "))
        check_for_vulnerabilities(ip, port)
    elif option == "4":
        network_range = input("Ingrese el rango de IP (ej. 192.168.1.0/24): ")
        scan_range(network_range)
    elif option == "5":
        ip = get_local_ip()
        detect_firewall(ip)
    elif option == "6":
        devices = scan_network(get_local_ip() + "/24")
        open_ports = scan_ports("192.168.100.1", [22, 80, 443])
        generate_html_report(devices, open_ports)
        print("Reporte HTML generado como 'scan_report.html'")
    elif option == "7":
        print("Saliendo...")
        exit()
    else:
        print("Opción no válida. Intente de nuevo.")
    
    menu()

if __name__ == "__main__":
    menu()
