# 🕵 Digital Forensics & Cybersecurity Basics – Field Notes

**Author:** Anubhav Mohandas
**Platform:** Windows & Kali Linux
**Purpose:** Practical notes from early learning in Digital Forensics (DF), Cyber Forensics (CF), and related cybersecurity concepts.
**Note:** This is a structured compilation of topics, commands, and tools mentioned during the learning journey, with explanations and relevant resources.

---

## 1️⃣ DF vs CF – Understanding the Basics

| Term                       | Description                                                                                      |
| -------------------------- | ------------------------------------------------------------------------------------------------ |
| **Digital Forensics (DF)** | Broad discipline focusing on acquiring, analyzing, and presenting evidence from digital devices. |
| **Cyber Forensics (CF)**   | Subset of DF, specifically investigating cybercrimes and network-related incidents.              |

---

## 2️⃣ Chain of Custody Principles

The **chain of custody** ensures evidence remains admissible in court by maintaining integrity from collection to presentation.

**Key Rules:**

1. **Keep in confinement** – Secure evidence in a controlled environment.
2. **Non-repudiation** – Maintain proof of authenticity so no one can deny involvement.
3. **No tampering** – Preserve the original state of the evidence.

---

## 3️⃣ Security vs Privacy

* **Security** → Protecting assets from unauthorized access (e.g., firewalls, encryption).
* **Privacy** → Protecting identity-specific and personal information from exposure.

---

## 4️⃣ Threat Types

| Threat                 | Description                                                         | Example                   |
| ---------------------- | ------------------------------------------------------------------- | ------------------------- |
| **Malware**            | Malicious software to disrupt, damage, or gain unauthorized access. | Trojan, Ransomware        |
| **Phishing**           | Fraudulent attempts to obtain sensitive information.                | Fake bank login page      |
| **Spear Phishing**     | Targeted phishing attack aimed at a specific person or group.       | CEO fraud email           |
| **Spoofing**           | Pretending to be someone else to mislead.                           | Email header manipulation |
| **Social Engineering** | Exploiting human behavior for access.                               | Fake IT support call      |

---

## 5️⃣ Common Tools & Concepts

* **Zphisher** → Tool for creating phishing pages
  🔗 [Download Zphisher](https://github.com/htr-tech/zphisher)

* **MITM (Man-in-the-Middle)** → Intercepting communication between two parties.

  * Technique: **ARP Spoofing/Poisoning**
    🔗 [Bettercap](https://www.bettercap.org/) or `arpspoof` in Kali.

* **Forensics Data Formats**

  * **PCAP** – Packet capture files (Wireshark, tcpdump)
  * **XDR** – Extended Detection & Response systems
  * **EDR** – Endpoint Detection & Response tools
  * **NGFW** – Next-Gen Firewalls
  * **DLP** – Data Loss Prevention systems

* **SIEM Recommendation**: [Wazuh](https://wazuh.com/)

* **Malware Analysis**

  * **Static Analysis** → Structural inspection without execution (e.g., using [Ghidra](https://ghidra-sre.org/))
  * **Dynamic Analysis** → Behavioral monitoring during execution (sandbox environments).

* **BOSS THE SOC** → Free SOC practice platform
  🔗 [BOSS the SOC](https://www.crowdstrike.com/freetools/boss-the-soc/)

* **SET (Social Engineering Toolkit)** → Phishing, credential harvesting
  🔗 [Download SET](https://github.com/trustedsec/social-engineer-toolkit)

---

## 6️⃣ Malware Types

1. **File-based** → Needs a file to execute (e.g., EXE trojan).
2. **File-less** → Resides in memory; doesn’t write malicious files to disk.
3. **Zero-click** → Exploits vulnerabilities without user interaction.

---

## 7️⃣ Special Terms

* **HTA Attack** – HTML Application file used to execute malicious code on Windows. 🔗 [Research HTA Attack](https://attack.mitre.org/techniques/T1173/)
* **Reverse Shell** – Hacker gains control by making the victim connect back to them.
* **netstat -A -n -o** – View active connections and process IDs to spot suspicious remote access.

---

## 8️⃣ Data Acquisition

* **Logical Acquisition** → Copies specific files/folders without free space.
* **Physical Acquisition** → Full disk copy including deleted data.
* **Faraday Bag** → Blocks all signals to an electronic device.

---

## 9️⃣ Important Notes

* **Ethical Hacking** → Offensive security
* **Cybersecurity** → Defensive security
* **SQL Injection** → Client-side attack
* **Event Viewer** → Logs system events; hackers may clear logs to hide tracks.

---

## 🔟 Research Topics

* **MITRE ATT\&CK** → [MITRE ATT\&CK Framework](https://attack.mitre.org/)
* **Mimikatz** → Tool for extracting passwords, hashes, PINs.
  🔗 [Mimikatz GitHub](https://github.com/gentilkiwi/mimikatz)

---

## 1️⃣1️⃣ Forensic Lifecycle

**Identification → Collection → Analysis → Documentation → Preservation**

---

## 1️⃣2️⃣ STRIDE Framework

| Category                   | Example                             |
| -------------------------- | ----------------------------------- |
| **Spoofing**               | Email spoofing via fake SMTP server |
| **Tampering**              | MITM altering data                  |
| **Repudiation**            | Denying performed actions           |
| **Information Disclosure** | Leaking sensitive data              |
| **Denial of Service**      | Server flooding                     |
| **Elevation of Privilege** | Exploiting UAC bypass               |

---

## 1️⃣3️⃣ Miscellaneous Security Concepts

* **WakeLock** – Android feature controlling background tasks.
* **MSFVenom → APK → JAR Signing → Zip Align → Keystore** – Android payload creation.
* **Data Certificate vs Digital Certificate** –

  * **Data Certificate** → Proof of a file/data’s authenticity.
  * **Digital Certificate** → Cryptographic proof of identity for secure communication.
* **Shodan** – Search engine for internet-connected devices.
  🔗 [Shodan](https://www.shodan.io/)
* **Protocol Downgrade Attack** – Forcing HTTPS to HTTP.

---

## 1️⃣4️⃣ Privilege Escalation

* **UAC Bypass** → User Access Control is bypassed to gain admin rights.
* **Botnets**:

  * **Zeus** – Banking trojan botnet
  * **Mirai** – IoT botnet

---

## 1️⃣5️⃣ Forensics Tools List

| Tool                   | Purpose                 | Download                                                         |
| ---------------------- | ----------------------- | ---------------------------------------------------------------- |
| Autopsy                | Digital forensics       | [Autopsy](https://www.autopsy.com/)                              |
| Cyber Triage           | Incident response       | [Cyber Triage](https://www.cybertriage.com/)                     |
| MAGNET Axiom           | Advanced forensics      | [Magnet Axiom](https://www.magnetforensics.com/products/axiom/)  |
| Belkasoft X            | Comprehensive DFIR      | [Belkasoft](https://belkasoft.com/)                              |
| MOBILedit              | Mobile device forensics | [MOBILedit](https://www.mobiledit.com/)                          |
| OSForensics            | Forensics toolkit       | [OSForensics](https://www.osforensics.com/)                      |
| Ghidra                 | Reverse engineering     | [Ghidra](https://ghidra-sre.org/)                                |
| OllyDbg                | Debugging tool          | [OllyDbg](http://www.ollydbg.de/)                                |
| x64dbg                 | Debugging tool          | [x64dbg](https://x64dbg.com/)                                    |
| Systools Mail Examiner | Email forensics         | [Mail Examiner](https://www.mailxaminer.com/)                    |
| Velociraptor           | Endpoint monitoring     | [Velociraptor](https://www.velocidex.com/)                       |
| FTK Imager             | Evidence acquisition    | [FTK Imager](https://accessdata.com/product-download/ftk-imager) |

---

## 1️⃣6️⃣ Belkasoft Practice Lab

Belkasoft offers a **30-day trial** and CTF challenges.

* **Download Trial:** [Belkasoft Trial](https://belkasoft.com/trial)
* **CTF Challenge:** [Belkasoft CTF May](https://belkasoft.com/ctf_may/chall)

---

## 1️⃣7️⃣ Anti-Forensics in Windows

Anti-forensics aims to make forensic investigation harder. Example repo:
🔗 [Windows Anti-Forensics Scripts](https://github.com/MikeHorn-git/WAFS)

---

## 1️⃣8️⃣ Event ID Reference

Microsoft list of **important Windows Event IDs**:
🔗 [Events to Monitor](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)

---

## 1️⃣9️⃣ Authentication Mechanisms

* **Password-based**
* **Multi-Factor (MFA)**
* **Certificate-based**
* **Biometric**

---

## 2️⃣0️⃣ Windows Local Account Password Change (Without Current Password)

**Scenario:** Windows system with a **local account** (not Microsoft-linked).

**Steps:**

1. Open **Command Prompt as Administrator**.
2. Run:

   ```cmd
   net user
   ```

   → Lists all local users.
3. Change password for a specific user:

   ```cmd
   net user USERNAME NEWPASSWORD
   ```

   Example:

   ```cmd
   net user anubhav Pass@123
   ```

   ✅ This does not ask for the current password.

---

If you want, I can also **add diagrams** for Chain of Custody, STRIDE, and Forensics Lifecycle so your GitHub page looks visually professional.
Do you want me to prepare that visual version too?
