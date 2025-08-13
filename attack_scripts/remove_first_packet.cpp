#include "PcapFileDevice.h"
#include "Packet.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>
#include <arpa/inet.h>

struct FlowKey {
    std::string srcIp;
    std::string dstIp;
    uint16_t srcPort{0};
    uint16_t dstPort{0};
    uint8_t protocol{0};
    uint8_t ipVersion{4};

    bool operator==(const FlowKey &other) const {
        return srcIp == other.srcIp && dstIp == other.dstIp && srcPort == other.srcPort &&
               dstPort == other.dstPort && protocol == other.protocol && ipVersion == other.ipVersion;
    }
};

namespace std {
template <> struct hash<FlowKey> {
    size_t operator()(const FlowKey &k) const noexcept {
        std::hash<std::string> hstr;
        std::hash<uint64_t> h64;
        size_t h = hstr(k.srcIp);
        h ^= hstr(k.dstIp) + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
        uint64_t ports = (static_cast<uint64_t>(k.srcPort) << 16) | static_cast<uint64_t>(k.dstPort);
        h ^= h64(ports) + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
        h ^= h64((static_cast<uint64_t>(k.protocol) << 8) | k.ipVersion) + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
        return h;
    }
};
} // namespace std

// Normalize keys so that src/dst are order-insensitive (bidirectional flow keys)
static inline FlowKey normalizeFlowKey(const FlowKey &k) {
    // Order endpoints by (ip,port) lexicographically
    bool swapNeeded = false;
    if (k.srcIp > k.dstIp) {
        swapNeeded = true;
    } else if (k.srcIp == k.dstIp && k.srcPort > k.dstPort) {
        swapNeeded = true;
    }

    if (!swapNeeded) return k;

    FlowKey out = k;
    std::swap(out.srcIp, out.dstIp);
    std::swap(out.srcPort, out.dstPort);
    return out;
}

static bool extractFlowKey(const pcpp::RawPacket &raw, FlowKey &key) {
    pcpp::Packet parsed(const_cast<pcpp::RawPacket *>(&raw));
    key = FlowKey{};

    auto *ipv4 = parsed.getLayerOfType<pcpp::IPv4Layer>();
    auto *ipv6 = parsed.getLayerOfType<pcpp::IPv6Layer>();
    if (ipv4 == nullptr && ipv6 == nullptr) {
        return false;
    }
    uint8_t ipVersion = (ipv4 != nullptr) ? 4 : 6;
    std::string srcIpStr;
    std::string dstIpStr;
    uint8_t proto = 0;
    if (ipVersion == 4) {
        srcIpStr = ipv4->getSrcIPAddress().toString();
        dstIpStr = ipv4->getDstIPAddress().toString();
        proto = ipv4->getIPv4Header()->protocol;
    } else {
        srcIpStr = ipv6->getSrcIPAddress().toString();
        dstIpStr = ipv6->getDstIPAddress().toString();
        proto = ipv6->getIPv6Header()->nextHeader;
    }

    uint16_t sport = 0, dport = 0;
    if (auto *tcp = parsed.getLayerOfType<pcpp::TcpLayer>(); tcp != nullptr) {
        sport = ntohs(tcp->getTcpHeader()->portSrc);
        dport = ntohs(tcp->getTcpHeader()->portDst);
    } else if (auto *udp = parsed.getLayerOfType<pcpp::UdpLayer>(); udp != nullptr) {
        sport = ntohs(udp->getUdpHeader()->portSrc);
        dport = ntohs(udp->getUdpHeader()->portDst);
    } else {
        // leave ports as 0 for non-TCP/UDP
    }

    key.srcIp = srcIpStr;
    key.dstIp = dstIpStr;
    key.srcPort = sport;
    key.dstPort = dport;
    key.protocol = proto;
    key.ipVersion = ipVersion;
    return true;
}

using FlowPackets = std::vector<pcpp::RawPacket>;

static void splitFileIntoFlows(const std::string &pcapPath,
                               std::unordered_map<FlowKey, FlowPackets> &byFiveTuple) {
    auto *reader = pcpp::IFileReaderDevice::getReader(pcapPath);
    if (reader == nullptr) {
        throw std::runtime_error("Cannot determine reader for file: " + pcapPath);
    }
    if (!reader->open()) {
        throw std::runtime_error("Cannot open file for reading: " + pcapPath);
    }

    pcpp::RawPacket raw;
    while (reader->getNextPacket(raw)) {
        FlowKey fkey;
        if (!extractFlowKey(raw, fkey)) {
            continue;
        }
        // Normalize keys to be direction-agnostic
        FlowKey nfkey = normalizeFlowKey(fkey);
        byFiveTuple[nfkey].push_back(raw);
    }
    reader->close();
}

struct OutputPacketRef {
    pcpp::RawPacket raw;
};

static timespec makeTimeSpec(int64_t sec, int64_t nsec) {
    timespec t{};
    t.tv_sec = sec;
    t.tv_nsec = nsec;
    return t;
}

static inline int cmpTimespec(const timespec &a, const timespec &b) {
    if (a.tv_sec != b.tv_sec) return (a.tv_sec < b.tv_sec) ? -1 : 1;
    if (a.tv_nsec != b.tv_nsec) return (a.tv_nsec < b.tv_nsec) ? -1 : 1;
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <input_pcap> <output_pcapng>\n";
        std::cerr << "Notes:\n";
        std::cerr << " - This tool removes the first packet of each flow in the input pcap file\n";
        std::cerr << " - Flows with only one packet are preserved unchanged\n";
        std::cerr << " - Output maintains the original timing of remaining packets\n";
        return 1;
    }

    std::string inputPath = argv[1];
    std::string outputPath = argv[2];

    try {
        std::unordered_map<FlowKey, FlowPackets> flowsBy5t;
        splitFileIntoFlows(inputPath, flowsBy5t);

        std::vector<OutputPacketRef> allOut;
        allOut.reserve(1024);

        size_t numFlows = 0, numModified = 0, numUnchanged = 0;

        for (const auto &kv : flowsBy5t) {
            numFlows++;
            const FlowKey &flowKey = kv.first;
            const FlowPackets &flow = kv.second;
            
            if (flow.empty()) continue;
            
            // If flow has only one packet, keep it unchanged
            if (flow.size() == 1) {
                numUnchanged++;
                OutputPacketRef ref{flow[0]};
                allOut.emplace_back(ref);
                continue;
            }

            // Remove first packet and keep the rest
            numModified++;
            for (size_t i = 1; i < flow.size(); ++i) {
                OutputPacketRef ref{flow[i]};
                allOut.emplace_back(ref);
            }
        }

        // Sort allOut by timestamp to produce a coherent timeline
        std::stable_sort(allOut.begin(), allOut.end(), [](const OutputPacketRef &a, const OutputPacketRef &b) {
            return cmpTimespec(a.raw.getPacketTimeStamp(), b.raw.getPacketTimeStamp()) < 0;
        });

        // Write to pcapng
        pcpp::PcapNgFileWriterDevice writer(outputPath);
        if (!writer.open()) {
            std::cerr << "Error opening output file: " << outputPath << std::endl;
            return 1;
        }
        for (auto &ref : allOut) {
            writer.writePacket(ref.raw);
        }
        writer.close();

        std::cout << "Processed flows: " << numFlows << "\n";
        std::cout << " - Flows modified (first packet removed): " << numModified << "\n";
        std::cout << " - Flows unchanged (single packet): " << numUnchanged << "\n";
        std::cout << "Output written to: " << outputPath << std::endl;
    } catch (const std::exception &ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
