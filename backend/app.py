from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from scapy.all import sniff, ARP, IP, DNS, Raw
from collections import defaultdict
from sklearn.ensemble import IsolationForest
from flask_socketio import SocketIO, emit
from flask_mail import Mail, Message
from twilio.rest import Client
import csv
import io
import os
import logging
import requests
from OpenSSL import crypto

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, cors_allowed_origins="*")

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'rr6022799@gmail.com'
app.config['MAIL_PASSWORD'] = 'ugfh ubik rmzr zugb'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)

# Configure Twilio
TWILIO_ACCOUNT_SID = 'your_account_sid'
TWILIO_AUTH_TOKEN = 'your_auth_token'
twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
TWILIO_PHONE_NUMBER = '+1234567890'
ADMIN_PHONE_NUMBER = '+0987654321'

packet_stats = defaultdict(int)
attack_packets = defaultdict(list)
captured_packets = []
historical_data = []
known_gateways = ["192.168.0.1"]
isolation_forest = IsolationForest(contamination=0.1)
is_capturing = False
known_dns_records = {"www.example.com": "93.184.216.34"}
known_certificates = {}  # Add your known certificates here

# Configure Logging
logging.basicConfig(level=logging.INFO, filename='nids.log', filemode='a', format='%(asctime)s - %(message)s')

# User credentials for authentication
users = {
    'admin': 'admin',
    'viewer': 'viewer'
}

@app.route('/')
def index():
    return "Network Intrusion Detection System Backend"

@app.route('/auth', methods=['POST'])
def auth():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if users.get(username) == password:
        return jsonify({'message': 'Authenticated', 'role': username})
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/start_capture', methods=['POST'])
def start_capture():
    global is_capturing
    is_capturing = True
    duration = request.json.get('duration', 60)
    sniff(prn=packet_callback, timeout=duration)
    return jsonify({'message': 'Packet capturing started.'})

@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    global is_capturing
    is_capturing = False
    return jsonify({'message': 'Packet capturing stopped.'})

@app.route('/download_packets', methods=['GET'])
def download_packets():
    try:
        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerow(["Source IP", "Destination IP", "Protocol Summary", "Attack Type"])
        for packet in captured_packets:
            cw.writerow([packet['src'], packet['dst'], packet['protocol'], packet.get('attack_type', 'N/A')])
        output = io.BytesIO()
        output.write(si.getvalue().encode('utf-8'))
        output.seek(0)
        return send_file(output, mimetype='text/csv', download_name='captured_packets.csv', as_attachment=True)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/network_attacks', methods=['GET'])
def network_attacks():
    return jsonify({
        'mitm_packets': packet_stats['mitm_packets'],
        'spoofing_packets': packet_stats['spoofing_packets'],
        'dns_spoofing_packets': packet_stats['dns_spoofing_packets'],
        'https_spoofing_packets': packet_stats['https_spoofing_packets'],
        'total_packets': packet_stats['total_packets']
    })

@app.route('/analyze_attacks', methods=['GET'])
def analyze_attacks():
    attack_type = request.args.get('type')
    if attack_type not in attack_packets:
        return jsonify([])
    return jsonify(attack_packets[attack_type])

@app.route('/logs', methods=['GET'])
def get_logs():
    with open('nids.log', 'r') as log_file:
        log_content = log_file.read()
    return jsonify({'logs': log_content})

@app.route('/fetch_threat_intelligence', methods=['GET'])
def fetch_threat_intelligence():
    api_url = "https://api.xforce.ibmcloud.com/api/alerts/urgency"
    headers = {"Authorization": "Bearer YOUR_API_KEY"}
    response = requests.get(api_url, headers=headers)
    if response.status_code == 200:
        return jsonify(response.json())
    else:
        return jsonify({'error': 'Failed to fetch threat intelligence'}), 500

@app.route('/block_ip', methods=['POST'])
def block_ip():
    ip = request.json.get('ip')
    automate_response(ip)
    return jsonify({'message': f'Blocked IP {ip}.'})

def automate_response(ip):
    os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")

def packet_callback(packet):
    global is_capturing
    if not is_capturing:
        return

    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        packet_stats['total_packets'] += 1

        data = {
            'total_packets': packet_stats['total_packets'],
            'src': ip_src,
            'dst': ip_dst,
            'protocol': packet.summary()
        }

        captured_packets.append(data)
        store_historical_data(data)

        # ARP Spoofing Detection
        if packet.haslayer(ARP):
            arp_src = packet[ARP].psrc
            arp_dst = packet[ARP].pdst
            if arp_src in known_gateways or arp_dst in known_gateways:
                packet_stats['mitm_packets'] += 1
                attack_details = {
                    'ip_src': ip_src,
                    'ip_dst': ip_dst,
                    'protocol': 'ARP',
                    'details': packet.summary(),
                    'attack_type': 'MITM (ARP Spoofing)'
                }
                attack_packets['mitm_attacks'].append(attack_details)
                log_attack('MITM (ARP Spoofing)', attack_details)
                data['attack_type'] = 'MITM (ARP Spoofing)'
                send_email(str(attack_details))
                send_sms(str(attack_details))
                automate_response(ip_src)

        # Spoofing Detection
        if packet.haslayer(IP) and packet[IP].src in known_gateways and packet[IP].dst not in known_gateways:
            packet_stats['spoofing_packets'] += 1
            attack_details = {
                'ip_src': ip_src,
                'ip_dst': ip_dst,
                'protocol': 'IP',
                'details': packet.summary(),
                'attack_type': 'Spoofing'
            }
            attack_packets['spoofing_attacks'].append(attack_details)
            log_attack('Spoofing', attack_details)
            data['attack_type'] = 'Spoofing'
            automate_response(ip_src)

        # DNS Spoofing Detection
        if packet.haslayer(DNS):
            dns_qry = packet[DNS].qd.qname.decode('utf-8') if packet[DNS].qd else ""
            dns_resp = packet[DNS].an.rdata if packet[DNS].an else ""
            if dns_qry in known_dns_records and dns_resp != known_dns_records[dns_qry]:
                packet_stats['dns_spoofing_packets'] += 1
                attack_details = {
                    'ip_src': ip_src,
                    'ip_dst': ip_dst,
                    'protocol': 'DNS',
                    'details': f"DNS Spoofing detected. Query: {dns_qry}, Response: {dns_resp}",
                    'attack_type': 'DNS Spoofing'
                }
                attack_packets['dns_spoofing_attacks'].append(attack_details)
                log_attack('DNS Spoofing', attack_details)
                data['attack_type'] = 'DNS Spoofing'
                automate_response(ip_src)

        # HTTPS Spoofing Detection
        if packet.haslayer(IP) and packet[IP].dport == 443:
            try:
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, packet[Raw].load)
                cert_fingerprint = cert.digest("sha256").decode("utf-8")
                if packet[IP].dst in known_certificates and known_certificates[packet[IP].dst] != cert_fingerprint:
                    packet_stats['https_spoofing_packets'] += 1
                    attack_details = {
                        'ip_src': ip_src,
                        'ip_dst': ip_dst,
                        'protocol': 'HTTPS',
                        'details': 'HTTPS Spoofing detected: Certificate mismatch',
                        'attack_type': 'HTTPS Spoofing'
                    }
                    attack_packets['https_spoofing_attacks'].append(attack_details)
                    log_attack('HTTPS Spoofing', attack_details)
                    data['attack_type'] = 'HTTPS Spoofing'
                    automate_response(ip_src)
            except Exception as e:
                pass

        socketio.emit('packet_data', data)

def log_attack(attack_type, details):
    logging.info(f"{attack_type} attack detected: {details}")

def store_historical_data(packet):
    historical_data.append(packet)

if __name__ == '__main__':
    socketio.run(app, debug=False)

# pip install flask flask-cors scapy sklearn flask-socketio flask-mail twilio
