# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/komlavidekpe/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that certain employees may be using the Tor browser to circumvent network security controls. Recent network logs reveal unusual encrypted traffic patterns and connections to known Tor entry nodes. Furthermore, anonymous reports suggest that some employees have discussed accessing restricted websites during work hours. The objective is to identify and confirm any instances of Tor usage, investigate related security events, and implement measures to mitigate potential risks. Any confirmed use of Tor should be promptly reported to management.
### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

An investigation was conducted by querying the DeviceFileEvents table for any file names containing the string “tor.” The results indicated that the user “osiris” downloaded a Tor installer, which subsequently caused multiple Tor-related files to be copied to the Desktop directory. In addition, a file named “tor-shopping-list.txt” was created on the Desktop. These activities were initiated at 2025-11-06T19:44:25.6920082Z.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessAccountName == "osiris"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-11-06T19:44:25.6920082Z)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account =InitiatingProcessAccountName
| order by Timestamp desc
```
<img width="919" height="424" alt="Screenshot 2025-11-06 at 8 12 21 PM" src="https://github.com/user-attachments/assets/63ec6041-316b-43b3-a112-80885e32a8ee" />


---

### 2. Searched the `DeviceProcessEvents` Table

A search of the DeviceProcessEvents table was performed for any ProcessCommandLine entries containing the string “tor-browser-windows-x86_64-portable-15.0.exe.” The investigation determined that on November 6, 2025, at 2:47:07 PM, the user “osiris” executed the file “tor-browser-windows-x86_64-portable-15.0.exe” from the Downloads folder on the device “threat-hunt-lab.” The file has a SHA-256 hash value of fd022504bb6e57e379668ed4b82966f284f19508dd88d76eaaf33e505add4f43 and was launched using a command indicative of a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1064" height="197" alt="Screenshot 2025-11-06 at 8 20 11 PM" src="https://github.com/user-attachments/assets/654e0146-2b66-40e9-9e99-e87d371ec305" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “osiris” opened the Tor Browser. Evidence confirmed that the browser was launched at 2025-11-06T19:48:20.7527139Z. Several subsequent instances of firefox.exe (Tor) and tor.exe processes were observed being spawned shortly afterward.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1043" height="331" alt="Screenshot 2025-11-06 at 8 23 46 PM" src="https://github.com/user-attachments/assets/1af0c242-638e-4f3c-83a6-df1f701d5ff9" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication that the Tor Browser was used to establish connections over known Tor network ports. At 2025-11-06T19:49:15.7059014Z, on the device “threat-hunt-lab,” the user “osiris” executed the file “tor.exe” located at C:\Users\Osiris\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe. This process initiated a network connection to the remote IP address 95.17.81.188 using port 9001, with several additional Tor-related connections observed shortly afterward.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "threat-hunt-lab"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1074" height="171" alt="Screenshot 2025-11-06 at 8 25 49 PM" src="https://github.com/user-attachments/assets/2398cef4-46d5-42fe-af22-0a1fe7565e3e" />


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** 2025-11-06T19:44:25.6920082Z
- **Event:** The user "osiris" downloaded a file named tor-browser-windows-x86_64-portable-15.0.exe to the Downloads folder.
- **Action:** File download detected.
- **File Path:** C:\Users\Osiris\Downloads\tor-browser-windows-x86_64-portable-15.0.exe


### 2. Process Execution - TOR Browser Installation

- **Timestamp:** 2025-11-06T19:47:07Z
- **Event:** The user "osiris" executed the file tor-browser-windows-x86_64-portable-15.0.exe in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** tor-browser-windows-x86_64-portable-15.0.exe /S
- **File Path:** C:\Users\Osiris\Downloads\tor-browser-windows-x86_64-portable-15.0.exe

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** 2025-11-06T19:48:20.7527139Z
- **Event:** The user "osiris" opened the TOR Browser. Multiple subsequent processes, including firefox.exe and tor.exe, were created, confirming that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** C:\Users\Osiris\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe

### 4. Network Connection - TOR Network

- **Timestamp:** 2025-11-06T19:49:15.7059014Z
- **Event:** A network connection to IP 95.17.81.188 on port 9001 by user "osiris" was established using tor.exe, confirming TOR network activity.
- **Action:** Connection success.
- **Process:** tor.exe
- **File Path:** C:\Users\Osiris\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
2025-11-06T19:49:16Z – Additional TOR-related connections observed.
2025-11-06T19:49:20Z – Continued TOR network communication detected.
- **Event:** Multiple outbound connections were established by tor.exe and firefox.exe, indicating ongoing TOR Browser activity and communication with TOR relay nodes.
- **Action:** Multiple successful network connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** 2025-11-06T19:49:30Z (approx.)
- **Event:** The user "osiris" created a file named tor-shopping-list.txt on the Desktop, potentially serving as notes or a record related to their TOR activity.
- **Action:** File creation detected.
- **File Path:** C:\Users\Osiris\Desktop\tor-shopping-list.txt

---

## Summary

The user "osiris" on the "threat-hunt-lab" device downloaded, installed, and launched the TOR Browser. Shortly after, the browser established outbound connections to known TOR network ports and remote IP addresses. The user also created a file named tor-shopping-list.txt on the desktop. These actions show that the user intentionally installed and used the TOR Browser, likely to browse the internet anonymously or hide online activity, and kept notes related to this activity in the created text file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `osiris`. The device was isolated, and the user's direct manager was notified.

---
