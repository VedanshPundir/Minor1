# Minor1
# GeoScan:Information gathering tool
Part of my first minor project on GeoScan: Information gathering tool

## Overview
GeoScan is a network scanning tool designed to gather information about wireless-connected devices on a network. This project focuses on collecting crucial data such as device IP addresses, MAC addresses, open ports, and version checks of various services. The tool is built in C++ without the use of external libraries or tools like Nmap, ensuring a lightweight and efficient solution for network administrators and security professionals.

## Features
- **Network Device Discovery**: Automatically detects all active devices connected to the network.
- **MAC Address Retrieval**: Displays the MAC addresses of all discovered devices.
- **Port Scanning**: Scans specified ports (e.g., 21, 80, 443, 8080, 53) to check for open services.
- **Version Check**: Retrieves the service version information for open ports.
- **Geolocation Mapping**: Displays geolocation data for detected IP addresses.

## Technologies Used
- C++
- POSIX Sockets
- pcap library for packet capturing

## Installation
To compile and run the GeoScan project on a Kali Linux system, follow these steps:

1. **Clone the repository**:
   ```bash
   git clone https://github.com/VedanshPundir/Minor1.git
   


   

