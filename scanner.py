import os
import socket
from scapy.all import ARP, Ether, srp

# Función 1: Escanear dispositivos en la red
def scan_network(target_ip):
    # Enviar solicitud ARP para obtener información de los dispositivos conectados
    print(f"Escaneando la red {target_ip}...")
    arp_request = ARP(pdst=target_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=10, verbose=False)[0]

    devices = []
    for element in answered_list:
        device_info = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        devices.append(device_info)
    
    print("\nDispositivos conectados en la red:")
    for device in devices:
        print(f"IP: {device['ip']} | MAC: {device['mac']}")
    
    return devices

# Función 2: Escanear puertos abiertos en un rango de puertos
def scan_ports(ip, start_port, end_port):
    open_ports = []
    print(f"Escaneando puertos en {ip} desde {start_port} hasta {end_port}...")
    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()

    print("\nPuertos abiertos:")
    if open_ports:
        for port in open_ports:
            print(f"Puerto {port} abierto")
    else:
        print("No se encontraron puertos abiertos.")
    
    return open_ports

# Función 3: Mostrar IPs y Dispositivos conectados (Función combinada de los primeros dos)
def network_info(target_ip):
    devices = scan_network(target_ip)
    for device in devices:
        # Cambié los puertos a un rango desde 1 hasta 1024 (o puedes ajustarlo a tus necesidades)
        scan_ports(device['ip'], 1, 1024)  # Escanea los puertos del 1 al 1024

# Función principal
if __name__ == "__main__":
    target_ip = "192.168.100.1/24"  # Define el rango de IPs de tu red
    network_info(target_ip)
