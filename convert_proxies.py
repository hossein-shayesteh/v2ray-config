import json
import yaml
import requests
from urllib.parse import urlparse, parse_qs, unquote
import base64
import time
import logging
import os
import re

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# In-memory cache to avoid hitting rate limit
geoip_cache = {}

def country_code_to_emoji(code):
    """Convert country code to emoji flag"""
    if not code or len(code) != 2:
        return "🌍"  
    return chr(0x1F1E6 + ord(code.upper()[0]) - ord('A')) + chr(0x1F1E6 + ord(code.upper()[1]) - ord('A'))

def get_country_flag(server):
    """Get country flag for server IP with caching and rate limiting"""
    try:
        # Extract IP from server:port format
        ip = server.split(':')[0] if ':' in server else server
        
        # Check cache first
        if ip in geoip_cache:
            return geoip_cache[ip]
        
        # Rate limiting - wait between requests
        time.sleep(0.1)
        
        # Make GeoIP request
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
        data = response.json()
        
        country_code = data.get('countryCode', 'XX')
        country_name = data.get('country', 'Unknown')
        emoji = country_code_to_emoji(country_code)
        
        # Cache the result
        geoip_cache[ip] = {'emoji': emoji, 'country': country_name, 'code': country_code}
        
        return geoip_cache[ip]
    except Exception as e:
        logger.warning(f"Failed to get geo info for {server}: {e}")
        return {'emoji': '🌍', 'country': 'Unknown', 'code': 'XX'}

class ProxyConverter:
    def __init__(self):
        self.supported_ciphers = ['auto', 'aes-128-gcm', 'chacha20-poly1305', 'none', 'zero']
        self.supported_networks = ['tcp', 'udp', 'ws', 'http', 'h2', 'grpc', 'quic']
    
    def convert_vless(self, url):
        """Convert VLESS URL to Clash proxy config"""
        try:
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            
            # Extract fragment (usually contains the name)
            fragment = unquote(parsed.fragment) if parsed.fragment else ""
            
            config = {
                'name': fragment or f"VLESS-{parsed.hostname}",
                'type': 'vless',
                'server': parsed.hostname,
                'port': int(parsed.port) if parsed.port else 443,
                'uuid': parsed.username,
                'udp': True,
                'tls': False,
                'skip-cert-verify': True,
                'servername': parsed.hostname
            }
            
            # Network type
            network = query.get('type', ['tcp'])[0].lower()
            if network in self.supported_networks:
                config['network'] = network
            else:
                config['network'] = 'tcp'
                logger.warning(f"Unsupported network type {network}, using tcp")
            
            # Security/TLS configuration
            security = query.get('security', [''])[0].lower()
            if security in ['tls', 'reality']:
                config['tls'] = True
                config['servername'] = query.get('sni', [parsed.hostname])[0]
                
                # ALPN
                if 'alpn' in query:
                    alpn = query['alpn'][0]
                    config['alpn'] = alpn.split(',') if ',' in alpn else [alpn]
                
                # Client fingerprint
                if 'fp' in query:
                    config['client-fingerprint'] = query['fp'][0]
            
            # Flow control for VLESS
            if 'flow' in query and query['flow'][0]:
                config['flow'] = query['flow'][0]
            
            # WebSocket specific options
            if network == 'ws':
                ws_opts = {}
                if 'path' in query:
                    ws_opts['path'] = unquote(query['path'][0])
                if 'host' in query:
                    ws_opts['headers'] = {'Host': query['host'][0]}
                config['ws-opts'] = ws_opts
            
            # gRPC specific options
            elif network == 'grpc':
                grpc_opts = {}
                if 'serviceName' in query:
                    grpc_opts['grpc-service-name'] = query['serviceName'][0]
                config['grpc-opts'] = grpc_opts
            
            # HTTP/2 specific options
            elif network == 'h2':
                h2_opts = {}
                if 'path' in query:
                    h2_opts['path'] = unquote(query['path'][0])
                if 'host' in query:
                    h2_opts['host'] = [query['host'][0]]
                config['h2-opts'] = h2_opts
            
            # Reality specific options
            if security == 'reality':
                reality_opts = {}
                if 'pbk' in query:
                    reality_opts['public-key'] = query['pbk'][0]
                if 'sid' in query:
                    reality_opts['short-id'] = query['sid'][0]
                config['reality-opts'] = reality_opts
            
            return config
            
        except Exception as e:
            logger.error(f"Failed to convert VLESS URL: {e}")
            return None
    
    def convert_vmess(self, url):
        """Convert VMess URL to Clash proxy config"""
        try:
            # Extract the base64 encoded part
            encoded_part = url.split('://')[1]
            if '#' in encoded_part:
                encoded_part = encoded_part.split('#')[0]
            
            # Add padding if needed
            padding = 4 - len(encoded_part) % 4
            if padding != 4:
                encoded_part += '=' * padding
            
            # Decode the configuration
            decoded = base64.urlsafe_b64decode(encoded_part).decode('utf-8')
            vmess_config = json.loads(decoded)
            
            # Extract fragment for name
            fragment = ""
            if '#' in url:
                fragment = unquote(url.split('#')[1])
            
            config = {
                'name': fragment or vmess_config.get('ps', f"VMess-{vmess_config['add']}"),
                'type': 'vmess',
                'server': vmess_config['add'],
                'port': int(vmess_config['port']),
                'uuid': vmess_config['id'],
                'alterId': int(vmess_config.get('aid', 0)),
                'udp': True,
                'skip-cert-verify': True
            }
            
            # Cipher
            cipher = vmess_config.get('type', 'auto').lower()
            if cipher in self.supported_ciphers:
                config['cipher'] = cipher
            else:
                config['cipher'] = 'auto'
                logger.warning(f"Unsupported cipher {cipher}, using auto")
            
            # Network type
            network = vmess_config.get('net', 'tcp').lower()
            if network in self.supported_networks:
                config['network'] = network
            else:
                config['network'] = 'tcp'
                logger.warning(f"Unsupported network {network}, using tcp")
            
            # TLS
            tls = vmess_config.get('tls', '').lower()
            if tls in ['tls', '1', 'true']:
                config['tls'] = True
                config['servername'] = vmess_config.get('sni', vmess_config['add'])
            
            # WebSocket options
            if network == 'ws':
                ws_opts = {}
                if vmess_config.get('path'):
                    ws_opts['path'] = vmess_config['path']
                if vmess_config.get('host'):
                    ws_opts['headers'] = {'Host': vmess_config['host']}
                config['ws-opts'] = ws_opts
            
            # HTTP/2 options
            elif network == 'h2':
                h2_opts = {}
                if vmess_config.get('path'):
                    h2_opts['path'] = vmess_config['path']
                if vmess_config.get('host'):
                    h2_opts['host'] = [vmess_config['host']]
                config['h2-opts'] = h2_opts
            
            # gRPC options
            elif network == 'grpc':
                grpc_opts = {}
                if vmess_config.get('path'):
                    grpc_opts['grpc-service-name'] = vmess_config['path']
                config['grpc-opts'] = grpc_opts
            
            return config
            
        except Exception as e:
            logger.error(f"Failed to convert VMess URL: {e}")
            return None
    
    def convert_trojan(self, url):
        """Convert Trojan URL to Clash proxy config"""
        try:
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            
            fragment = unquote(parsed.fragment) if parsed.fragment else ""
            
            config = {
                'name': fragment or f"Trojan-{parsed.hostname}",
                'type': 'trojan',
                'server': parsed.hostname,
                'port': int(parsed.port) if parsed.port else 443,
                'password': parsed.username,
                'udp': True,
                'skip-cert-verify': True
            }
            
            # SNI
            if 'sni' in query:
                config['sni'] = query['sni'][0]
            
            # ALPN
            if 'alpn' in query:
                alpn = query['alpn'][0]
                config['alpn'] = alpn.split(',') if ',' in alpn else [alpn]
            
            # Network type
            network = query.get('type', ['tcp'])[0].lower()
            if network == 'ws':
                ws_opts = {}
                if 'path' in query:
                    ws_opts['path'] = unquote(query['path'][0])
                if 'host' in query:
                    ws_opts['headers'] = {'Host': query['host'][0]}
                config['network'] = 'ws'
                config['ws-opts'] = ws_opts
            elif network == 'grpc':
                grpc_opts = {}
                if 'serviceName' in query:
                    grpc_opts['grpc-service-name'] = query['serviceName'][0]
                config['network'] = 'grpc'
                config['grpc-opts'] = grpc_opts
            
            return config
            
        except Exception as e:
            logger.error(f"Failed to convert Trojan URL: {e}")
            return None

def parse_proxies_from_file(filename):
    """Parse proxy URLs from file and convert them"""
    converter = ProxyConverter()
    proxies = []
    
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        logger.info(f"Found {len(lines)} lines in {filename}")
        
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            proxy = None
            try:
                if line.startswith('vless://'):
                    proxy = converter.convert_vless(line)
                elif line.startswith('vmess://'):
                    proxy = converter.convert_vmess(line)
                elif line.startswith('trojan://'):
                    proxy = converter.convert_trojan(line)
                else:
                    logger.warning(f"Line {i}: Unsupported protocol in URL: {line[:50]}...")
                    continue
                
                if proxy:
                    proxies.append(proxy)
                    logger.info(f"Line {i}: Successfully converted {proxy['type'].upper()} proxy")
                else:
                    logger.error(f"Line {i}: Failed to convert proxy")
                    
            except Exception as e:
                logger.error(f"Line {i}: Error processing URL: {e}")
                continue
        
        logger.info(f"Successfully converted {len(proxies)} proxies")
        
        # Add geo information and update names with your format: 🇮🇷 VMess 01
        for i, proxy in enumerate(proxies):
            try:
                geo_info = get_country_flag(proxy['server'])
                protocol = proxy['type'].upper()
                
                # Format: (Country flag emoji) (Protocol) (Number)
                proxy['name'] = f"{geo_info['emoji']} {protocol} {i+1:02d}"
                
            except Exception as e:
                logger.warning(f"Failed to add geo info for proxy {i}: {e}")
                protocol = proxy['type'].upper()
                proxy['name'] = f"🌍 {protocol} {i+1:02d}"
        
        # Remove duplicates based on server:port combination
        seen = set()
        unique_proxies = []
        for proxy in proxies:
            key = f"{proxy['server']}:{proxy['port']}"
            if key not in seen:
                seen.add(key)
                unique_proxies.append(proxy)
            else:
                logger.info(f"Removed duplicate proxy: {proxy['name']}")
        
        logger.info(f"Final proxy count after deduplication: {len(unique_proxies)}")
        return unique_proxies
        
    except FileNotFoundError:
        logger.error(f"Config file {filename} not found")
        return []
    except Exception as e:
        logger.error(f"Error parsing proxies from file: {e}")
        return []

def load_config_template(template_file):
    """Load the Mihomo/Clash config template"""
    try:
        with open(template_file, 'r', encoding='utf-8') as f:
            if template_file.endswith('.json'):
                return json.load(f)
            else:
                return yaml.safe_load(f)
    except FileNotFoundError:
        logger.error(f"Template file {template_file} not found")
        return None

def main():
    """Main execution function"""
    logger.info("Starting proxy conversion process...")
    
    # Parse proxies from file
    proxies = parse_proxies_from_file('V2RayConfigs')
    
    if not proxies:
        logger.error("No valid proxies found, exiting...")
        return
    
    # Load template - specifically look for mihomo-config.json first
    template = load_config_template('mihomo-config.json')
    
    if not template:
        logger.error("Could not load mihomo-config.json template file!")
        return
    
    logger.info("Successfully loaded mihomo-config.json template")
    
    # Update template with proxies
    template['proxies'] = proxies
    
    # Update proxy groups - replace placeholder proxies with real ones
    proxy_names = [proxy['name'] for proxy in proxies]
    
    if 'proxy-groups' in template:
        for group in template['proxy-groups']:
            if 'proxies' in group:
                # Remove placeholder proxies (proxy1, proxy2, proxy3)
                existing_proxies = [p for p in group['proxies'] if not p.startswith('proxy')]
                # Add real proxy names
                group['proxies'] = existing_proxies + proxy_names
                logger.info(f"Updated proxy group '{group['name']}' with {len(proxy_names)} proxies")
    
    # Create output directory
    os.makedirs('generated', exist_ok=True)
    
    # Write the final configuration as YAML (Mihomo prefers YAML)
    output_file = 'generated/clashConfig.yaml'
    with open(output_file, 'w', encoding='utf-8') as f:
        yaml.safe_dump(template, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
    
    logger.info(f"Generated Mihomo configuration with {len(proxies)} proxies: {output_file}")
    
    # Print summary
    print(f"\n✅ Successfully generated Mihomo config:")
    print(f"   📁 File: {output_file}")
    print(f"   🌐 Proxies: {len(proxies)}")
    print(f"   🗂️  Groups: {len(template.get('proxy-groups', []))}")
    
    # Print proxy summary by type
    proxy_types = {}
    for proxy in proxies:
        proxy_type = proxy['type'].upper()
        proxy_types[proxy_type] = proxy_types.get(proxy_type, 0) + 1
    
    print(f"   📊 By type: {', '.join([f'{k}: {v}' for k, v in proxy_types.items()])}")
    
    # Print some example proxy names
    if proxies:
        print(f"   📝 Examples: {', '.join([p['name'] for p in proxies[:3]])}{'...' if len(proxies) > 3 else ''}")

if __name__ == "__main__":
    main()