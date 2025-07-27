import json
import yaml
import requests
from urllib.parse import urlparse, parse_qs
import base64
import time
import logging

# In-memory cache to avoid hitting rate limit
geoip_cache = {}

# Country code to emoji
def country_code_to_emoji(code):
    if not code or len(code) != 2:
        return "🇺🇳"  
    return chr(0x1F1E6 + ord(code.upper()[0]) - ord('A')) + chr(0x1F1E6 + ord(code.upper()[1]) - ord('A'))

# GeoIP helper function
def get_country_flag(server):
    try:
        ip = server.split(':')[0] if ':' in server else server
        if ip in geoip_cache:
            return geoip_cache[ip]
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5).json()
        country_code = response.get('countryCode', 'XX')
        emoji = country_code_to_emoji(country_code)
        flag = f"{emoji} {country_code.upper()}"
        geoip_cache[ip] = flag
        return flag
    except Exception:
        return "🇺🇳 UNKNOWN"

# VLESS/VMess URL parser
class ProxyConverter:
    def convert_vless(self, url):
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        
        config = {
            'name': '',  # Will be set later
            'type': 'vless',
            'server': parsed.hostname,
            'port': parsed.port,
            'uuid': parsed.username,
            'udp': True,
        'flow': flow if flow else '-',
            'tfo': False,
            'ip-version': 'dual',
            'network': query.get('type', ['tcp'])[0],
            'tls': 'security' in query and query['security'][0] in ['tls', 'reality'],
            'client-fingerprint': query.get('fp', ['chrome'])[0],
            'smux': {
                'enabled': True,
                'protocol': 'h2mux',
                'padding': True
            }
        }

        # TLS specific parameters
        if config['tls']:
            config.update({
                'sni': query.get('sni', [parsed.hostname])[0],
                'alpn': query.get('alpn', ['h2'])[0].split(',')
            })

        # Protocol specific options
        if config['network'] == 'ws':
            config['ws-opts'] = {
                'path': unquote(query.get('path', ['/'])[0]),
                'headers': {
                    'Host': query.get('host', [parsed.hostname])[0]
                }
            }
        elif config['network'] == 'grpc':
            config['grpc-opts'] = {
                'grpc-service-name': query.get('serviceName', [''])[0]
            }

        # Reality configuration
        if 'reality' in query.get('security', []):
            config.update({
                'reality-opts': {
                    'public-key': query.get('pbk', [''])[0],
                    'short-id': query.get('sid', [''])[0]
                }
            })

        return config


import urllib.parse

logger = logging.getLogger(__name__)

def parse_proxies_from_file(filename):
    try:
        with open(filename, 'r') as f:
            proxies = []
            for line in f:
                line = line.strip()
                if line.startswith('vless://') or line.startswith('vmess://'):
                    proxies.append(convert_proxy_url(line))
            # Add geo lookup and naming
        for i, proxy in enumerate(proxies):
            country = get_country_flag(proxy['server'])
            proxy['name'] = f"{country} {proxy['type'].upper()} {i+1:02d}"
        
        # Remove duplicates
        seen = set()
        return [p for p in proxies if not (p['name'] in seen or seen.add(p['name']))]
    except FileNotFoundError:
        logger.error(f"Config file {filename} not found")
        raise


def convert_proxy_url(url):
    parsed = urllib.parse.urlparse(url)
    protocol = parsed.scheme
    
    if protocol == 'vless':
        return convert_vless(url)
    elif protocol == 'vmess':
        return convert_vmess(url)
    else:
        raise ValueError(f'Unsupported protocol: {protocol}')


def convert_vmess(url):
    decoded = base64.urlsafe_b64decode(url.split('://')[1].split('#')[0] + '==').decode()
    config = json.loads(decoded)

    # All validation happens BEFORE return statement
    allowed_ciphers = ['auto', 'aes-128-gcm', 'chacha20-poly1305', 'none']
    cipher = str(config.get('type', 'auto')).lower()
    
    if cipher not in allowed_ciphers:
        cipher = 'auto'
        logger.warning(f'Unsupported VMESS cipher: {config["type"]}')

    return {
        'name': '',
        'type': 'vmess',
        'server': config['add'],
        'port': int(config['port']),
        'uuid': config['id'],
        'alterId': int(config.get('aid', 0)),
        'cipher': cipher,  # Now properly formatted
        'network': config.get('net', 'tcp'),
        'tls': 'tls' in config.get('tls', '')
    }

# VLESS requires flow control
def convert_vless(url):
    parsed = urllib.parse.urlparse(url)
    # Extract cipher from URL parameters
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    return {
        'name': '',  # To be filled from geo lookup
        'type': 'vless',
        'server': parsed.hostname,
        'port': int(parsed.port),
        'uuid': parsed.username,
        'network': parsed.fragment.split('#')[0] or '-',
        'servername': parsed.hostname  # Required for Reality configs
    }

# Main conversion logic
# Correct execution order
proxies = parse_proxies_from_file('V2RayConfigs')  # Parse first

template = json.load(open('mihomo-config.json'))  # Load template after

if proxies:
    template['proxies'] = proxies  # Safe assignment
else:
    print("No proxies found")  # Graceful error handling

# Then process proxy groups
if 'proxy-groups' in template:
    for group in template['proxy-groups']:
        # Auto-populate all proxy groups with actual proxies
        group['proxies'] = [proxy['name'] for proxy in proxies]  # Use parsed proxies list

# Update template and write YAML
# Create output directory if not exists
import os
os.makedirs('generated', exist_ok=True)

with open('generated/clashConfig.yaml', 'w', encoding='utf-8') as f:
    yaml.safe_dump(template, f, allow_unicode=True)
