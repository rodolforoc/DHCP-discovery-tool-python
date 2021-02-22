import logging
import subprocess
import re

try:
    from scapy.all import *

except ImportError:
    print("Scapy não está instalado no sistema.")
    print("Tente usando: sudo pip3.8 install scapy")
    sys.exit()

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

conf.checkIPaddr = False

# Lendo servidores DHCP permitidos de um arquivo externo
with open("dhcp.txt") as f:
    allowed_dhcp_servers = f.read()

# Listando todas as interfaces de rede
host_if = subprocess.run(["ip link"], shell = True, stdout = subprocess.PIPE)

# Extraindo o nome das interfaces da resposta acima
interfaces = re.findall(r"\d:\s(.+?):\s", str(host_if))

# Detectando servidores DHCP por interface(exceto interface loopback)
for interface in interfaces:
    if interface != "lo":
        # Pegando o endereço de hardware
        hw = get_if_raw_hwaddr(interface)[1]
        #print(hw)

        # Criando pacote de descoberta DHCP
        dhcp_discover = Ether(dst = "ff:ff:ff:ff:ff:ff") / IP(src = "0.0.0.0", dst = "255.255.255.255") / UDP(sport = 68, dport = 67) / BOOTP(chaddr = hw) / DHCP(options = [("message-type", "discover"), "end"])

        # Enviando pacote de descoberta e aceitando multiplas respostas
        ans, unans = srp(dhcp_discover, multi = True, iface = interface, timeout = 5, verbose = 0)
        #print(ans)
        #print(unans)

        # Criando dicionário para armazenar os Mac-ip
        mac_ip = {}

        for pair in ans:
            #print(pair)
        	mac_ip[pair[1][Ether].src] = pair[1][IP].src

        if ans:
            print("\n--> Os seguintes servidores DHCP foram encontrados em {} LAN:\n".format(interface))

            for mac, ip in mac_ip.items():
                if ip in allowed_dhcp_servers:
                    print("OK! Endereço de IP: {}, Endereço MAC: {}\n".format(ip, mac))
                else:
                    print("ROGUE! Endereço de IP: {}, Endereço MAC: {}\n".format(ip, mac))

        else:
            print("\n--> Nenhum servidor DHCP ativo encontrado na {} LAN.\n".format(interface))

    else:
        pass
