import socket
from datetime import datetime

def port_scanner(target_ip, start_port, end_port):
    print(f"Scanning target {target_ip} for ports {start_port}-{end_port}")
    print(f"Started at {datetime.now()}")
    print("-" * 60)
    print(f"{'PORT':<10} {'STATUS':<10} {'SERVICE'}")
    print("-" * 60)

    # Common ports service name
    common_ports = {21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS", 80:"HTTP", 443:"HTTPS", 3306:"MySQL"}

    for port in range(start_port, end_port + 1):
        # Step 1: Import socket & create socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Step 3: Set timeout
        s.settimeout(1) 
        
        # Step 3: Attempt TCP handshake
        result = s.connect_ex((target_ip, port))
        
        if result == 0:
            # Step 4: Open port
            service = common_ports.get(port, "Unknown")
            try:
                # Try to get banner / service responsiveness
                s.send(b'Hello\r\n')
                banner = s.recv(1024).decode().strip()
                if banner:
                    service += f" - {banner[:30]}"
            except:
                pass
            print(f"{port:<10} {'OPEN':<10} {service}")
        else:
            # You can show closed also if needed, but for clean output we show only open
            # To show Closed/Filtered table as per task, uncomment below
            # print(f"{port:<10} {'CLOSED':<10}")
            pass
            
        s.close()
    
    print("-" * 60)
    print("Scan Completed.")

# Step 2: Accept target IP and port range
if __name__ == "__main__":
    target = input("Enter Target IP (ex: 127.0.0.1 or scanme.nmap.org): ") or "127.0.0.1"
    try:
        target_ip = socket.gethostbyname(target)
    except:
        target_ip = target
        
    start = int(input("Enter Start Port (ex: 1): ") or 1)
    end = int(input("Enter End Port (ex: 100): ") or 100)
    
    port_scanner(target_ip, start, end)
