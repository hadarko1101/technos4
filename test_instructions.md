# Docker Test Environment Instructions

## 1. Start the Environment
Open a terminal in the directory where `docker-compose.yml` is located (`c:\Users\TLP-001\Desktop\Technos\ex4`) and run:
```bash
docker-compose up -d --build
```

## 2. Configure the Constants
Update your `ex4_skeleton.py` to match the exact IPs used in the instructions and Docker network. Replace the `???` values with these:

```python
DOOFENSHMIRTZ_IP = "10.0.2.15"       # Victim container (VirtualBox Default NAT First IP)
SECRATERY_IP = "10.0.2.16"           # Attacker container
NETWORK_DNS_SERVER_IP = "10.0.2.43"  # Dummy DNS Server from PDF
IFACE = "eth0"                       # Docker network interface
SPOOF_DICT = {
    b"mail.doofle.com": FAKE_GMAIL_IP # The fake site
}
```
*Note: Depending on how Scapy parses DNS, you might need a trailing dot like `b"mail.doofle.com."`.*

## 3. Run the Attacker Scripts
Open a terminal **inside the attacker container**:
```bash
docker exec -it spoof_attacker bash
```
Start the web server in the background:
```bash
python server/app.py &
```
Run your spoofing script:
```bash
python ex4_skeleton.py
```

## 4. Test from the Victim
You can run this one-liner from your Windows terminal to instantly test if the DNS and HTTP spoofing is working:
```bash
docker exec spoof_victim bash -c "echo -n 'doofle IP: ' && dig mail.doofle.com +short | tail -n1 && echo -n 'google IP: ' && dig google.com +short | tail -n1 && if curl -s http://mail.doofle.com | grep -q 'save_password'; then echo '[+] Spoofed content verified'; fi && if ! curl -L -s http://google.com | grep -q 'save_password'; then echo '[+] Google connection OK (Not spoofed)'; fi"
```
*(Or open a terminal inside the container with `docker exec -it spoof_victim bash` and run them manually).*

## 5. View from your Host Machine
Because we exposed port 80 in `docker-compose.yml`, you can directly open a web browser on your Windows machine and go to:
[http://localhost](http://localhost)
This will hit the Flask app running inside the attacker container!
