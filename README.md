# V2Ray to Mihomo/Clash Meta Configuration Converter

This repository automatically converts V2Ray proxy configurations (VLESS, VMess, Trojan) into optimized Mihomo/Clash Meta YAML configurations. The system uses GitHub Actions to automatically generate updated configurations whenever the source V2Ray configs are modified.

## 🚀 Features

### Automated Conversion

- **Multi-Protocol Support:** Converts VLESS, VMess, and Trojan protocols
- **Smart Naming:** Proxies are automatically named with country flags and sequential numbers (e.g., `🇺🇸 VLESS 01`)
- **Geographic Detection:** Uses IP-based geolocation to add country flags to proxy names
- **Duplicate Removal:** Automatically filters out duplicate servers
- **GitHub Actions Integration:** Automatic conversion triggered on file changes

### Mihomo/Clash Meta Optimizations

- **Iranian Smart Routing:** Optimized rules for Iranian users with direct routing for local domains
- **Advanced DNS Configuration:** Fake-IP mode with fallback DNS servers
- **TUN Mode Support:** Full system proxy with traffic hijacking
- **Security Features:** Built-in ad blocking, malware protection, and phishing prevention
- **Load Balancing:** Multiple proxy group strategies (URL test, load balance, manual select)

### Network Protocol Support

- **Transport Protocols:** TCP, WebSocket (WS), HTTP/2, gRPC, QUIC
- **Security:** TLS, Reality obfuscation
- **Advanced Features:** Flow control, ALPN, SNI, client fingerprinting

## 📁 Repository Structure

```
├── .github/workflows/
│   └── generate-clash-config.yml    # GitHub Actions workflow
├── convert_proxies.py               # Main conversion script
├── mihomo-config.json              # Mihomo template configuration
├── V2RayConfigs                    # Source V2Ray proxy URLs (one per line)
└── generated/
    ├── clashConfig.yaml            # Generated Mihomo configuration
    └── README.md                   # Auto-generated documentation
```

## 🔄 How It Works

1. **Source Update:** When `V2RayConfigs` file is updated with new proxy URLs
2. **Auto-Trigger:** GitHub Actions workflow automatically starts
3. **Conversion Process:**
   - Downloads latest V2Ray configurations
   - Parses VLESS/VMess/Trojan URLs
   - Converts to Mihomo proxy format
   - Adds geographic information and country flags
   - Generates optimized YAML configuration
4. **Output:** New `clashConfig.yaml` ready for use

## 📱 Compatible Clients

### Desktop Applications

- **Mihomo** (Recommended)
- **Clash Verge Rev**
- **ClashX Pro** (macOS)
- **Clash for Windows** (Deprecated)

### Mobile Applications

- **ClashMeta for Android** (Recommended)
- **Clash for Android**
- **Stash** (iOS)
- **Shadowrocket** (iOS - partial support)

## 🛠️ Usage Instructions

### Method 1: Direct Download

1. Go to the [Generated Configurations](./generated/) folder
2. Download `clashConfig.yaml`
3. Import into your Mihomo/Clash Meta client

### Method 2: Subscription URL

Use this raw GitHub URL as subscription in your client:

```
https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/generated/clashConfig.yaml
```

### Method 3: GitHub Artifacts

1. Go to [Actions](../../actions) tab
2. Click on latest workflow run
3. Download the `clash-config` artifact

## ⚙️ Configuration Details

### Proxy Groups

- **Smart VPN:** Manual selection with all available options
- **Auto:** Automatic selection based on latency (URL test)
- **Load Balancer:** Distributes traffic across multiple proxies

### DNS Configuration

- **Mode:** Fake-IP for better performance
- **Upstream:** Multiple DNS providers (Cloudflare, Google, Quad9)
- **Fallback:** DOH/DOQ support with filtering
- **Hijacking:** Automatic DNS traffic capture in TUN mode

### Routing Rules

- **Iranian Domains:** Direct connection (bypass proxy)
- **Private Networks:** Direct connection
- **Ad/Malware Blocking:** Automatic rejection of malicious domains
- **International Traffic:** Routed through Smart VPN

### Security Features

- **Rule Providers:** Auto-updating rules from trusted sources
- **Malware Protection:** Domain and IP-based blocking
- **Ad Blocking:** Comprehensive ad domain filtering
- **Phishing Protection:** Real-time phishing domain blocking

## 🔧 Development

### Adding New Proxies

1. Edit the `V2RayConfigs` file
2. Add new proxy URLs (one per line)
3. Commit changes - GitHub Actions will automatically generate new config

### Customizing Template

1. Modify `mihomo-config.json` to change default settings
2. Adjust DNS servers, ports, or routing rules as needed
3. Commit changes to apply to future generations

### Local Development

```bash
# Install dependencies
pip install pyyaml requests

# Run conversion locally
python convert_proxies.py

# Check generated output
cat generated/clashConfig.yaml
```

## 📊 Statistics

The system automatically tracks and reports:

- Total number of proxies converted
- Breakdown by protocol type (VLESS/VMess/Trojan)
- Geographic distribution of servers
- Conversion success/failure rates
- Generated file sizes and proxy counts

## 🛡️ Privacy & Security

### Rate Limiting

- Geographic lookups are rate-limited to respect API limits
- Caching system prevents duplicate API calls
- Graceful fallback for failed geo lookups

### Security Features

- No logging of sensitive proxy details
- Automatic certificate verification skipping for compatibility
- Built-in protection against malicious domains and IPs

### Data Sources

- **Iranian Rules:** [Chocolate4U/Iran-clash-rules](https://github.com/Chocolate4U/Iran-clash-rules)
- **Domain Lists:** [bootmortis/iran-hosted-domains](https://github.com/bootmortis/iran-hosted-domains)
- **GeoIP Service:** ip-api.com (with caching and rate limiting)

## 🤝 Contributing

1. **Adding Proxies:** Submit PRs with new URLs in `V2RayConfigs`
2. **Improving Conversion:** Enhance the `convert_proxies.py` script
3. **Template Updates:** Modify `mihomo-config.json` for better defaults
4. **Documentation:** Help improve this README and generated docs

## ⚠️ Important Notes

### Requirements

- **Mihomo/Clash Meta:** Required for full feature support
- **Admin Privileges:** Needed for TUN mode on desktop systems
- **Recent Client:** Older Clash versions may not support all features

### Limitations

- Some advanced Reality features may require specific client versions
- iOS clients have varying levels of Mihomo feature support
- TUN mode configuration may need adjustment for different operating systems

### Legal Compliance

- **Personal Use Only:** These configurations are for personal use
- **Local Laws:** Ensure compliance with local regulations
- **No Warranties:** Use at your own risk and responsibility

## 📞 Support

- **Issues:** Use GitHub Issues for bug reports and feature requests
- **Discussions:** GitHub Discussions for questions and community support
- **Updates:** Watch repository for automatic notifications

---

**Last Updated:** Auto-generated by GitHub Actions  
**Template Version:** Mihomo/Clash Meta optimized  
**Supported Protocols:** VLESS, VMess, Trojan  
**Target Clients:** Mihomo, Clash Meta, compatible forks
