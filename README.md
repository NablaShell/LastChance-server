# Last Chance Server 

A high-performance, privacy-focused dual-node relay system built with Go. Designed for secure, asynchronous data exchange with a zero-footprint architecture.

## Architecture Overview

The system consists of two specialized nodes orchestrated by a Caddy reverse proxy:
- **SMS Relay (Node):** Handles lightweight message queuing using an in-memory SQLite provider and Ed25519 cryptographic authorization.
- **File Relay (File API):** Manages temporary file storage with a hybrid RAM/Disk approach and secure deletion (shredding).
- **Caddy Proxy:** Acts as the "Stealth Layer," handling SSL (TLS 1.3), anti-scanning headers, and request filtering.

## Security Features

- **Asynchronous Stealth:** Uses custom header validation at the proxy level to drop unauthorized requests silently (403/404).
- **Crypto-Auth:** All pull operations require Ed25519 signatures based on the identity hash.
- **Auto-Purge:** Files and messages have strict TTL (Time-To-Live). One-time download policy: data is shredded immediately after delivery.
- **Anti-Forensics:** Integrated `shred` utility support for overwriting disk sectors before file unlinking.
- **No-Log Policy:** Application logs are minimized and focused on operational health.

## Deployment

1. **Configure Environment:**
   Copy `env.example` to `.env` and fill in your domain, stealth headers, and secrets.

2. **Run Infrastructure:**
   ```bash
   docker compose up -d --build
   ```

### Security Audit & Feedback

This is an open-source project dedicated to secure communications. We highly encourage community audits. If you find vulnerabilities or have suggestions regarding:

 - Ed25519 implementation logic.
 - Race conditions in the FileStore mutexes.
 - Proxy bypass techniques.

Please reach out via the secure channels below.

### Support & Donation

If this project helped you stay connected, consider supporting the maintenance:

    
| Asset | Address |
| :--- | :--- |
| **BTC** | 8Arc4tRdGAKcWNMLCb7mj2fnYqWgQGhTTgR7FEGaZpL2Pw6MNSwqsGMUGpeQGURgQbDoyxU1ASKMP7dKBJq8yJgCSwCgPYe |
| **XMR** | bc1qktffxm3579v6zs6mpms4yvwp6m067nkggd8ach |

*All donations go towards relay nodes and security audits.*

### Contact & Feedback

   Session ID: 05f08d7242fe9cd621e98ef902cd1a21a8bf10d0c7c946e8c8e469d2396657a637

   ProtonMail: nabla.shell@proton.me

   PGP Public Key: [here](https://github.com/NablaShell/LastChance/docs/public_key.asc) 
   
   *PGP Fingerprint: 885F 3675 1D87 3F99 55ED 0ABC D1F6 A559 1458 507D*


##  License
This project is licensed under the **AGPL-3.0 License** - see the LICENSE file for details.
