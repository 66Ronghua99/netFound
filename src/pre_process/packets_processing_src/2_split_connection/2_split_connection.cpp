#include "PcapFileDevice.h"
#include "Packet.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include <iostream>
#include <string>
#include <map>
#include <set>
#include <filesystem>
#include <sstream>
#include <iomanip>
#include <arpa/inet.h>

// Connection identifier structure
struct ConnectionKey {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    std::string protocol;
    
    // Create filename-friendly string
    std::string toFilename() const {
        std::ostringstream oss;
        oss << "connection-" << protocol << "_" 
            << src_ip << "_" << src_port << "-"
            << dst_ip << "_" << dst_port;
        return oss.str();
    }
    
    // For map comparison
    bool operator<(const ConnectionKey& other) const {
        if (src_ip != other.src_ip) return src_ip < other.src_ip;
        if (dst_ip != other.dst_ip) return dst_ip < other.dst_ip;
        if (src_port != other.src_port) return src_port < other.src_port;
        if (dst_port != other.dst_port) return dst_port < other.dst_port;
        return protocol < other.protocol;
    }
};

class ConnectionSplitter {
private:
    std::string inputFile;
    std::string outputDir;
    std::map<ConnectionKey, std::vector<pcpp::RawPacket>> connections;
    std::set<std::string> uniqueIPs;
    
public:
    ConnectionSplitter(const std::string& input, const std::string& output) 
        : inputFile(input), outputDir(output) {}
    
    bool processFile() {
        auto* reader = pcpp::IFileReaderDevice::getReader(inputFile);
        if (reader == nullptr) {
            std::cerr << "Cannot determine reader for file: " << inputFile << std::endl;
            return false;
        }
        
        if (!reader->open()) {
            std::cerr << "Cannot open " << inputFile << " for reading" << std::endl;
            return false;
        }
        
        std::cout << "Processing file: " << inputFile << std::endl;
        
        pcpp::RawPacket rawPacket;
        int packetCount = 0;
        
        while (reader->getNextPacket(rawPacket)) {
            packetCount++;
            if (packetCount % 10000 == 0) {
                std::cout << "Processed " << packetCount << " packets..." << std::endl;
            }
            
            pcpp::Packet parsedPacket(&rawPacket);
            auto* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
            
            if (ipLayer != nullptr) {
                std::string srcIP = ipLayer->getSrcIPAddress().toString();
                std::string dstIP = ipLayer->getDstIPAddress().toString();
                
                // Track all unique IPs
                uniqueIPs.insert(srcIP);
                uniqueIPs.insert(dstIP);
                
                ConnectionKey connKey;
                
                // Handle TCP packets
                auto* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
                if (tcpLayer != nullptr) {
                    connKey.src_ip = srcIP;
                    connKey.dst_ip = dstIP;
                    connKey.src_port = ntohs(tcpLayer->getTcpHeader()->portSrc);
                    connKey.dst_port = ntohs(tcpLayer->getTcpHeader()->portDst);
                    connKey.protocol = "tcp";
                    
                    connections[connKey].push_back(rawPacket);
                }
                // Handle UDP packets
                else {
                    auto* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
                    if (udpLayer != nullptr) {
                        connKey.src_ip = srcIP;
                        connKey.dst_ip = dstIP;
                        connKey.src_port = ntohs(udpLayer->getUdpHeader()->portSrc);
                        connKey.dst_port = ntohs(udpLayer->getUdpHeader()->portDst);
                        connKey.protocol = "udp";
                        
                        connections[connKey].push_back(rawPacket);
                    }
                }
            }
        }
        
        reader->close();
        std::cout << "Total packets processed: " << packetCount << std::endl;
        std::cout << "Total unique connections found: " << connections.size() << std::endl;
        std::cout << "Total unique IPs: " << uniqueIPs.size() << std::endl;
        
        return true;
    }
    
    bool writeConnections() {
        // Create output directory if it doesn't exist
        std::filesystem::create_directories(outputDir);
        
        std::cout << "Writing " << connections.size() << " connection files to: " << outputDir << std::endl;
        
        int fileCount = 0;
        for (const auto& [connKey, packets] : connections) {
            fileCount++;
            if (fileCount % 100 == 0) {
                std::cout << "Written " << fileCount << " files..." << std::endl;
            }
            
            std::string filename = connKey.toFilename() + ".pcapng";
            std::string filepath = outputDir + "/" + filename;
            
            auto* writer = new pcpp::PcapNgFileWriterDevice(filepath);
            if (!writer->open()) {
                std::cerr << "Error opening output file: " << filepath << std::endl;
                delete writer;
                continue;
            }
            
            // Write all packets for this connection
            for (const auto& packet : packets) {
                writer->writePacket(packet);
            }
            
            writer->close();
            delete writer;
        }
        
        std::cout << "Successfully wrote " << fileCount << " connection files" << std::endl;
        return true;
    }
    
    void printStatistics() {
        std::cout << "\n=== CONNECTION STATISTICS ===" << std::endl;
        std::cout << "Total unique connections: " << connections.size() << std::endl;
        std::cout << "Total unique IPs: " << uniqueIPs.size() << std::endl;
        
        // Count connections by source IP
        std::map<std::string, int> srcIPCounts;
        std::map<std::string, int> dstIPCounts;
        
        for (const auto& [connKey, packets] : connections) {
            srcIPCounts[connKey.src_ip]++;
            dstIPCounts[connKey.dst_ip]++;
        }
        
        std::cout << "\nTop 10 source IPs by connection count:" << std::endl;
        std::vector<std::pair<std::string, int>> srcIPs(srcIPCounts.begin(), srcIPCounts.end());
        std::sort(srcIPs.begin(), srcIPs.end(), 
                  [](const auto& a, const auto& b) { return a.second > b.second; });
        
        for (int i = 0; i < std::min(10, (int)srcIPs.size()); i++) {
            std::cout << "  " << srcIPs[i].first << ": " << srcIPs[i].second << " connections" << std::endl;
        }
        
        std::cout << "\nTop 10 destination IPs by connection count:" << std::endl;
        std::vector<std::pair<std::string, int>> dstIPs(dstIPCounts.begin(), dstIPCounts.end());
        std::sort(dstIPs.begin(), dstIPs.end(), 
                  [](const auto& a, const auto& b) { return a.second > b.second; });
        
        for (int i = 0; i < std::min(10, (int)dstIPs.size()); i++) {
            std::cout << "  " << dstIPs[i].first << ": " << dstIPs[i].second << " connections" << std::endl;
        }
        
        std::cout << "\nAll unique IPs (" << uniqueIPs.size() << " total):" << std::endl;
        for (const auto& ip : uniqueIPs) {
            std::cout << "  " << ip << std::endl;
        }
    }
};

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <input_pcap_file> <output_directory>" << std::endl;
        std::cerr << "Example: " << argv[0] << " input.pcapng output_connections/" << std::endl;
        return 1;
    }
    
    std::string inputFile = argv[1];
    std::string outputDir = argv[2];
    
    // Check if input file exists
    if (!std::filesystem::exists(inputFile)) {
        std::cerr << "Input file does not exist: " << inputFile << std::endl;
        return 1;
    }
    
    ConnectionSplitter splitter(inputFile, outputDir);
    
    if (!splitter.processFile()) {
        std::cerr << "Failed to process input file" << std::endl;
        return 1;
    }
    
    if (!splitter.writeConnections()) {
        std::cerr << "Failed to write connection files" << std::endl;
        return 1;
    }
    
    splitter.printStatistics();
    
    std::cout << "\nConnection splitting completed successfully!" << std::endl;
    return 0;
}
