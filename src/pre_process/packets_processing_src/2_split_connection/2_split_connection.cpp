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
#include <functional>

// Hash function for connection identification
struct ConnectionHash {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    std::string protocol;
    
    // Create a unique hash for the connection
    size_t hash() const {
        std::hash<std::string> string_hash;
        std::hash<uint16_t> port_hash;
        
        // Combine all connection parameters into a single hash
        size_t h = string_hash(src_ip);
        h ^= string_hash(dst_ip) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= port_hash(src_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= port_hash(dst_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= string_hash(protocol) + 0x9e3779b9 + (h << 6) + (h >> 2);
        
        return h;
    }
    
    // Create filename-friendly string
    std::string toFilename() const {
        std::ostringstream oss;
        oss << "connection-" << protocol << "_" 
            << src_ip << "_" << src_port << "-"
            << dst_ip << "_" << dst_port;
        return oss.str();
    }
    
    // For map comparison (using hash as key)
    bool operator<(const ConnectionHash& other) const {
        return hash() < other.hash();
    }
    
    // Equality comparison
    bool operator==(const ConnectionHash& other) const {
        return src_ip == other.src_ip && 
               dst_ip == other.dst_ip && 
               src_port == other.src_port && 
               dst_port == other.dst_port && 
               protocol == other.protocol;
    }
};

// Hash function for std::unordered_map (if needed)
namespace std {
    template<>
    struct hash<ConnectionHash> {
        size_t operator()(const ConnectionHash& conn) const {
            return conn.hash();
        }
    };
}

class ConnectionSplitter {
private:
    std::string inputFile;
    std::string outputDir;
    std::map<ConnectionHash, std::vector<pcpp::RawPacket>> connections;
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
                
                ConnectionHash connHash;
                
                // Handle TCP packets
                auto* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
                if (tcpLayer != nullptr) {
                    connHash.src_ip = srcIP;
                    connHash.dst_ip = dstIP;
                    connHash.src_port = ntohs(tcpLayer->getTcpHeader()->portSrc);
                    connHash.dst_port = ntohs(tcpLayer->getTcpHeader()->portDst);
                    connHash.protocol = "tcp";
                    
                    connections[connHash].push_back(rawPacket);
                }
                // Handle UDP packets
                else {
                    auto* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
                    if (udpLayer != nullptr) {
                        connHash.src_ip = srcIP;
                        connHash.dst_ip = dstIP;
                        connHash.src_port = ntohs(udpLayer->getUdpHeader()->portSrc);
                        connHash.dst_port = ntohs(udpLayer->getUdpHeader()->portDst);
                        connHash.protocol = "udp";
                        
                        connections[connHash].push_back(rawPacket);
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
		
		// Count connections eligible for writing (at least 2 packets)
		size_t eligibleCount = 0;
		for (const auto& entry : connections) {
			if (entry.second.size() >= 2) {
				eligibleCount++;
			}
		}
		
		std::cout << "Writing " << eligibleCount << " connection files to: " << outputDir << std::endl;
		
		int fileCount = 0;
		for (const auto& [connKey, packets] : connections) {
			// Skip flows with fewer than 2 packets
			if (packets.size() < 2) {
				continue;
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
			
			fileCount++;
			if (fileCount % 100 == 0) {
				std::cout << "Written " << fileCount << " files..." << std::endl;
			}
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
        
        for (const auto& [connHash, packets] : connections) {
            srcIPCounts[connHash.src_ip]++;
            dstIPCounts[connHash.dst_ip]++;
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
