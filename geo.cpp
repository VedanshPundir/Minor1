#include <algorithm> // Ensure this is included first
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <iostream>

// C Headers
#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <netinet/ip_icmp.h>

// Additional Headers for Banner Grabbing
#include <sys/select.h>
#include <errno.h>

// Prevent C's remove and find from interfering with C++'s std::remove and std::find
#ifdef remove
#undef remove
#endif

#ifdef find
#undef find
#endif

// Mutex for thread-safe console output
std::mutex coutMutex;

// Mutex for thread-safe devices vector access
std::mutex devicesMutex;

// Structure to hold device information
struct Device {
    std::string ip;
    std::string status;
    std::string mac;
    std::string version;
};

// Function to calculate checksum for ICMP header
unsigned short calculateChecksum(unsigned short *buf, int len) {
    unsigned long sum = 0;
    while(len > 1){
        sum += *buf++;
        len -= 2;
    }
    if(len == 1){
        sum += *(unsigned char*)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

// Function to get the first active non-loopback network interface
std::string getActiveInterface() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *device;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        exit(EXIT_FAILURE);
    }

    // Iterate through devices and select the first suitable one
    for (device = alldevs; device != nullptr; device = device->next) {
        std::string devName = device->name;
        // Skip loopback and special interfaces
        if (devName.find("lo") != std::string::npos ||
            devName.find("any") != std::string::npos ||
            devName.find("bluetooth") != std::string::npos ||
            devName.find("nflog") != std::string::npos ||
            devName.find("nfqueue") != std::string::npos ||
            devName.find("dbus") != std::string::npos) {
            continue;
        }

        {
            std::lock_guard<std::mutex> lock(coutMutex);
            std::cout << "Using interface: " << devName << std::endl;
        }

        std::string selectedInterface = devName;
        pcap_freealldevs(alldevs);
        return selectedInterface;
    }

    pcap_freealldevs(alldevs);
    std::cerr << "No suitable network interface found." << std::endl;
    exit(EXIT_FAILURE);
}

// Function to retrieve the local IP address associated with a network interface
std::string getLocalIPAddress(const std::string& interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *dev;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        exit(EXIT_FAILURE);
    }

    std::string localIP = "";
    for (dev = alldevs; dev != nullptr; dev = dev->next) {
        if (dev->name == interface) {
            pcap_addr_t *address = dev->addresses;
            while (address != nullptr) {
                if (address->addr->sa_family == AF_INET) {
                    struct sockaddr_in *sa_in = (struct sockaddr_in *)address->addr;
                    localIP = inet_ntoa(sa_in->sin_addr);
                    break;
                }
                address = address->next;
            }
            break;
        }
    }

    pcap_freealldevs(alldevs);

    if (localIP.empty()) {
        std::cerr << "Could not retrieve local IP address for interface: " << interface << std::endl;
        exit(EXIT_FAILURE);
    }

    return localIP;
}

// Function to send an ICMP echo request (ping) to a target IP
bool pingIP(const std::string& ipAddress) {
    int sockfd;
    struct sockaddr_in addr;
    struct icmphdr icmpHeader;
    char sendPacket[sizeof(struct icmphdr)];
    char recvPacket[1024];
    struct timeval timeout;

    // Create raw socket for ICMP
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket");
        return false;
    }

    // Set socket options for timeout
    timeout.tv_sec = 1;  // 1 second timeout
    timeout.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt");
        close(sockfd);
        return false;
    }

    // Configure destination address
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, ipAddress.c_str(), &addr.sin_addr);

    // Prepare ICMP header
    memset(&icmpHeader, 0, sizeof(icmpHeader));
    icmpHeader.type = ICMP_ECHO;
    icmpHeader.code = 0;
    icmpHeader.un.echo.id = getpid();
    icmpHeader.un.echo.sequence = 1;
    icmpHeader.checksum = 0;

    // Calculate checksum
    icmpHeader.checksum = calculateChecksum((unsigned short*)&icmpHeader, sizeof(icmpHeader));

    // Send ICMP echo request
    memcpy(sendPacket, &icmpHeader, sizeof(icmpHeader));
    if (sendto(sockfd, sendPacket, sizeof(sendPacket), 0, (struct sockaddr*)&addr, sizeof(addr)) <= 0) {
        perror("sendto");
        close(sockfd);
        return false;
    }

    // Wait for ICMP echo reply
    socklen_t addr_len = sizeof(addr);
    int bytesReceived = recvfrom(sockfd, recvPacket, sizeof(recvPacket), 0, (struct sockaddr*)&addr, &addr_len);
    if (bytesReceived <= 0) {
        // Timeout or error
        close(sockfd);
        return false;
    }

    // Process received packet
    struct iphdr *ip = (struct iphdr*)recvPacket;
    struct icmphdr *icmp = (struct icmphdr*)(recvPacket + (ip->ihl * 4));

    close(sockfd);

    if (icmp->type == ICMP_ECHOREPLY) {
        return true;
    }

    return false;
}

// Function to retrieve MAC address from ARP table
std::string getMACAddress(const std::string& ip) {
    FILE* arpCache = fopen("/proc/net/arp", "r");
    if (arpCache == nullptr) {
        perror("fopen");
        return "N/A";
    }

    char line[256];
    std::string mac = "N/A";

    // Skip the first line (header)
    if (fgets(line, sizeof(line), arpCache) == nullptr) {
        fclose(arpCache);
        return mac;
    }

    while (fgets(line, sizeof(line), arpCache)) {
        char ipInCache_c[32];
        char hwType[8];
        char flags[8];
        char macAddr[18];
        char mask[18];
        char device[16];

        // Correctly use sscanf with C-style strings
        int ret = sscanf(line, "%31s %7s %7s %17s %17s %15s", 
                         ipInCache_c, hwType, flags, macAddr, mask, device);
        if (ret != 6) {
            continue; // Malformed line; skip to the next
        }

        std::string ipInCache(ipInCache_c);

        if (ipInCache == ip) {
            mac = std::string(macAddr);
            break;
        }
    }

    fclose(arpCache);
    return mac;
}

// Function to set a timeout on the socket
bool setSocketTimeout(int sockfd, int seconds) {
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    return setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)) == 0;
}

// *** Enhanced getVersionInfo Function ***
std::string getVersionInfo(int sockfd) {
    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));

    // Set a timeout of 5 seconds for receiving data
    if (!setSocketTimeout(sockfd, 5)) {
        perror("setsockopt failed");
        return "N/A";
    }

    // Attempt to receive data from the socket
    int bytesReceived = recv(sockfd, buffer, sizeof(buffer) - 1, 0); // Removed MSG_DONTWAIT
    if (bytesReceived > 0) {
        std::string version(buffer, bytesReceived);
        // Clean up the version string by removing newline and carriage return characters
        version.erase(std::remove(version.begin(), version.end(), '\n'), version.end());
        version.erase(std::remove(version.begin(), version.end(), '\r'), version.end());
        return version;
    } else if (bytesReceived == 0) {
        // Connection closed by the server
        return "Connection closed by server";
    } else {
        // An error occurred
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            return "Timeout";
        }
        perror("recv failed");
        return "N/A";
    }
}
// *** End of Enhanced getVersionInfo Function ***

// Function to scan a range of IP addresses within a subnet
void scanRange(const std::string& subnet, int start, int end, std::vector<Device>& devices) {
    for (int i = start; i <= end; ++i) {
        std::string targetIP = subnet + std::to_string(i);
        bool alive = pingIP(targetIP);
        if (alive) {
            // Allow ARP cache to update
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            std::string mac = getMACAddress(targetIP);

            // Only add device if MAC is valid (not "N/A" and not "00:00:00:00:00:00")
            if (mac != "N/A" && mac != "00:00:00:00:00:00") {
                Device device;
                device.ip = targetIP;
                device.status = "Alive";
                device.mac = mac;
                device.version = "N/A"; // Initialize with "N/A"

                // Lock before modifying the devices vector
                {
                    std::lock_guard<std::mutex> lock(devicesMutex);
                    devices.push_back(device);
                }

                // Lock before printing to console
                {
                    std::lock_guard<std::mutex> lock(coutMutex);
                    std::cout << "Device found at: " << targetIP 
                              << " | MAC: " << mac << std::endl;
                }
            }
        }
    }
}

// Function to scan specified ports on a detected device using multithreading and perform banner grabbing
void scanPorts(Device& device, const std::vector<int>& ports) {
    {
        std::lock_guard<std::mutex> lock(coutMutex);
        std::cout << "\nScanning ports for IP: " << device.ip << std::endl;
    }

    const int MAX_CONCURRENT_THREADS = 50; // Adjust as needed
    std::vector<std::thread> threads;
    std::mutex versionMutex;

    // Lambda function to scan a single port
    auto scanPort = [&](int port) {
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            perror("socket");
            return;
        }

        struct sockaddr_in target;
        memset(&target, 0, sizeof(target));
        target.sin_family = AF_INET;
        target.sin_port = htons(port);
        inet_pton(AF_INET, device.ip.c_str(), &target.sin_addr);

        // Set timeout for connect
        struct timeval timeout;
        timeout.tv_sec = 1;  // 1 second timeout
        timeout.tv_usec = 0;
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

        // Try to connect
        if (connect(sockfd, (struct sockaddr*)&target, sizeof(target)) == 0) {
            // Optional: Send a request if the service requires it
            // For example, for HTTP ports, send a HEAD request
            std::string request;
            if (port == 80 || port == 443) { // HTTP or HTTPS
                request = "HEAD / HTTP/1.0\r\n\r\n";
                send(sockfd, request.c_str(), request.length(), 0);
            }

            // Perform banner grabbing
            std::string banner = getVersionInfo(sockfd);

            {
                std::lock_guard<std::mutex> lock(versionMutex);
                if (banner != "N/A" && banner != "Timeout") {
                    if (device.version == "N/A") {
                        device.version = banner;
                    } else {
                        device.version += " | " + banner;
                    }
                } else {
                    if (device.version == "N/A") {
                        device.version = "Open Port: " + std::to_string(port);
                    } else {
                        device.version += " | Open Port: " + std::to_string(port);
                    }
                }
            }

            // Print open port information
            {
                std::lock_guard<std::mutex> lock(coutMutex);
                std::cout << "Port " << port << " open on " << device.ip;
                if (banner != "N/A" && banner != "Timeout") {
                    std::cout << " | Version: " << banner;
                }
                std::cout << std::endl;
            }
        }

        close(sockfd);
    };

    for (const auto& port : ports) {
        threads.emplace_back(scanPort, port);

        // Limit the number of concurrent threads
        if (threads.size() >= MAX_CONCURRENT_THREADS) {
            for (auto& th : threads) {
                if (th.joinable()) th.join();
            }
            threads.clear();
        }
    }

    // Join any remaining threads
    for (auto& th : threads) {
        if (th.joinable()) th.join();
    }

    // If no version info was retrieved, set it to "N/A"
    if (device.version.empty()) {
        device.version = "N/A";
    }
}

int main() {
    // Ensure the program is run with root privileges
    if (geteuid() != 0) {
        std::cerr << "Please run this program as root." << std::endl;
        return EXIT_FAILURE;
    }

    // Dynamically select the active network interface
    std::string interface = getActiveInterface();

    // Retrieve the local IP address associated with the selected interface
    std::string localIP = getLocalIPAddress(interface);
    std::cout << "Local IP Address: " << localIP << std::endl;

    // Derive the subnet (assuming a /24 subnet)
    size_t lastDot = localIP.find_last_of('.');
    if (lastDot == std::string::npos) {
        std::cerr << "Invalid local IP address format." << std::endl;
        return EXIT_FAILURE;
    }

    std::string subnet = localIP.substr(0, lastDot + 1);
    std::cout << "Scanning subnet: " << subnet << "1 - " << subnet << "254" << std::endl;

    // Vector to store detected devices
    std::vector<Device> devices;

    // Multithreading parameters
    const int THREAD_COUNT = 10;
    int rangeSize = 254 / THREAD_COUNT;
    std::vector<std::thread> threads;

    // Launch threads to perform ping sweep
    for (int i = 0; i < THREAD_COUNT; ++i) {
        int start = i * rangeSize + 1;
        int end = (i == THREAD_COUNT - 1) ? 254 : (i + 1) * rangeSize;
        threads.emplace_back(scanRange, subnet, start, end, std::ref(devices));
    }

    // Join all threads
    for (auto& th : threads) {
        if (th.joinable()) {
            th.join();
        }
    }

    // Display all detected devices
    std::cout << "\nDevices found on the network:" << std::endl;
    int index = 1;
    std::vector<std::string> deviceIPs;
    for (auto& device : devices) {
        std::cout << index << ": " << device.ip 
                  << " | MAC: " << device.mac 
                  << " | Version: " << device.version 
                  << std::endl;
        deviceIPs.push_back(device.ip);
        index++;
    }

    if (deviceIPs.empty()) {
        std::cout << "No devices detected on the network." << std::endl;
        return EXIT_SUCCESS;
    }

    // Prompt user to select devices to scan ports
    std::cout << "\nEnter the numbers of the devices you want to scan for open ports (comma-separated, e.g., 1,3,5): ";
    std::string input;
    std::getline(std::cin, input);

    // Parse user input
    std::vector<int> selectedIndices;
    size_t pos = 0;
    while ((pos = input.find(',')) != std::string::npos) {
        std::string token = input.substr(0, pos);
        try {
            int num = std::stoi(token);
            selectedIndices.push_back(num - 1);
        } catch (...) {
            std::lock_guard<std::mutex> lock(coutMutex);
            std::cerr << "Invalid input: " << token << std::endl;
        }
        input.erase(0, pos + 1);
    }
    if (!input.empty()) {
        try {
            int num = std::stoi(input);
            selectedIndices.push_back(num - 1);
        } catch (...) {
            std::lock_guard<std::mutex> lock(coutMutex);
            std::cerr << "Invalid input: " << input << std::endl;
        }
    }

    // Validate and collect selected IPs
    std::vector<std::string> selectedIPs;
    for (int idx : selectedIndices) {
        if (idx >= 0 && idx < deviceIPs.size()) {
            selectedIPs.push_back(deviceIPs[idx]);
        } else {
            std::lock_guard<std::mutex> lock(coutMutex);
            std::cerr << "Invalid device number: " << (idx + 1) << std::endl;
        }
    }

    if (selectedIPs.empty()) {
        std::cout << "No valid devices selected for port scanning." << std::endl;
        return EXIT_SUCCESS;
    }

    // Define the specific ports to scan
    std::vector<int> specificPorts = {80, 443, 20, 21, 22, 110, 995, 143, 993, 53,8080,8005};

    // Scan open ports on each selected device
    for (auto& device : devices) {
        // Check if the device is selected
        if (std::find(selectedIPs.begin(), selectedIPs.end(), device.ip) != selectedIPs.end()) {
            scanPorts(device, specificPorts);
        }
    }

    // Display final results
    std::cout << "\nFinal Results:" << std::endl;
    index = 1;
    for (auto& device : devices) {
        if (std::find(selectedIPs.begin(), selectedIPs.end(), device.ip) != selectedIPs.end()) {
            std::cout << index << ": " << device.ip 
                      << " | MAC: " << device.mac 
                      << " | Version: " << device.version 
                      << std::endl;
            index++;
        }
    }

    return 0;
}

