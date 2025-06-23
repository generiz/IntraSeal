# IntraSeal - Internal Security Framework

**Author:** Nicolás Pintos  
**Website:** [www.nicolaspintos.com](https://www.nicolaspintos.com)  
**Version:** 1.0

---

## 🔐 Overview

**IntraSeal** is a lightweight internal security tool for Windows environments. It scans all `.exe` files in a target folder (and subfolders), and:

- ❌ Blocks each executable's outbound network access via Windows Firewall
- ✅ Optionally excludes the folder from Windows Defender scans
- 📄 Generates a detailed execution log
- 🌐 Optionally opens the author's website at the end of the process

---

## 📦 Features

- Fully written in **PowerShell**
- No third-party dependencies required
- Silent execution with **log output to Desktop**
- Optional popup to visit the author's website
- Visual branding using ASCII art at launch

---

## 🚀 Usage

1. **Run as Administrator**  
   This is required for modifying firewall rules and Defender settings.

2. **Execute the script:**

```powershell
.\IntraSeal.ps1 -TargetFolder "C:\Path\To\Folder"
```

If no path is provided, it will default to the current directory.

3. **Expected Result:**

- All `.exe` files inside the target directory will be blocked from accessing the internet.
- If Windows Defender is active, the folder will be excluded from scans.
- A log will be created on your Desktop as `IntraSeal_log.txt`.
- A popup may ask if you'd like to visit the author's website.

---

## 🛠️ Requirements

- Windows 10 or higher
- PowerShell 5.1+
- Administrator privileges

---

## 🔍 How to Confirm It Worked

To verify that the executables were blocked:

```powershell
Get-NetFirewallRule | Where-Object DisplayName -like "IntraSeal_*"
```

To verify if Defender exclusion was added:

```powershell
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
```

(You must run these as Administrator)

---

## ⚠️ Disclaimer

This script is provided as-is for internal use, testing, and educational purposes.  
Always ensure compliance with security policies, organizational standards, and legal guidelines.

---

## 📫 Contact

For questions, suggestions, or collaborations, visit:  
👉 [www.nicolaspintos.com](https://www.nicolaspintos.com)
