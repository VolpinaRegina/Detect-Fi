# Detect-Fi
WiFi devices distance detector
(V2 available)

While on monitor mode your chosen wireless interface can sniff every frame that comunicates via 802.11 protocol, this tool logs unique devices based on their MAC address and via technical infos given from the antenna itself it can calculate the relative distance of each device using the Free Space Path Loss formula.

---
### Use cases
[*] Environment: office

[*] Blue Team PoV: you can log every employee MAC address and legit APs and constantly monitor for amy relveant changes, such as an unidentified device that can result in an unauthorized access to the area, you can detect EvilTwin attacks etc..

[*] Red Team PoV: this tool requires sudo privileges on a Linux machine and at least one wirless interface, given that you hacked your way into this machine you can use this tool to do physical recon to better understand the routine of the people inside the office, when they're present, absent or on "coffe break", this helps plan a phisycal attack to the local systems in the office and go unseen, with the MAC addresses you can check for known OUI of security devices such as cameras and their relative distance

---
This tool is like a CCTV camera, its limit is that a CCTV is fixed and can't move usually, this tool has its own limit, it can see devices on any direction but only if such device is actively using the 802.11 protocol

### Enjoy
