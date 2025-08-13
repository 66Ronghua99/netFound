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
#include <random>

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

struct IpProtoKey {
    std::string srcIp;
    std::string dstIp;
    uint8_t protocol{0};
    uint8_t ipVersion{4};
    bool operator==(const IpProtoKey &o) const {
        return srcIp == o.srcIp && dstIp == o.dstIp && protocol == o.protocol && ipVersion == o.ipVersion;
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
template <> struct hash<IpProtoKey> {
    size_t operator()(const IpProtoKey &k) const noexcept {
        std::hash<std::string> hstr;
        std::hash<uint64_t> h64;
        size_t h = hstr(k.srcIp);
        h ^= hstr(k.dstIp) + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
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

static inline IpProtoKey normalizeIpProtoKey(const IpProtoKey &k) {
    bool swapNeeded = (k.srcIp > k.dstIp);
    IpProtoKey out = k;
    if (swapNeeded) std::swap(out.srcIp, out.dstIp);
    return out;
}

static bool extractFlowKey(const pcpp::RawPacket &raw, FlowKey &key, IpProtoKey &ipKey) {
    pcpp::Packet parsed(const_cast<pcpp::RawPacket *>(&raw));
    key = FlowKey{};
    ipKey = IpProtoKey{};

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

    ipKey.srcIp = srcIpStr;
    ipKey.dstIp = dstIpStr;
    ipKey.protocol = proto;
    ipKey.ipVersion = ipVersion;
    return true;
}

using FlowPackets = std::vector<pcpp::RawPacket>;

static void splitFileIntoFlows(const std::string &pcapPath,
                               std::unordered_map<FlowKey, FlowPackets> &byFiveTuple,
                               std::unordered_map<IpProtoKey, std::vector<FlowPackets *>> &byIpProto) {
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
        IpProtoKey ipkey;
        if (!extractFlowKey(raw, fkey, ipkey)) {
            continue;
        }
        // Normalize keys to be direction-agnostic
        FlowKey nfkey = normalizeFlowKey(fkey);
        IpProtoKey nipkey = normalizeIpProtoKey(ipkey);
        // Determine if this is a new flow (to avoid inserting duplicate pointers into byIpProto)
        auto it = byFiveTuple.find(nfkey);
        bool isNew = (it == byFiveTuple.end());
        auto &vec = byFiveTuple[nfkey];
        vec.push_back(raw);
        if (isNew) {
            byIpProto[nipkey].push_back(&vec);
        }
    }
    reader->close();
}

struct OutputPacketRef {
    // Keep either a RawPacket (copied) or a Packet-owned RawPacket
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

static void addNanos(timespec &t, int64_t deltaNanos) {
    int64_t sec = t.tv_sec;
    int64_t nsec = t.tv_nsec + deltaNanos;
    sec += nsec / 1000000000LL;
    nsec %= 1000000000LL;
    if (nsec < 0) {
        nsec += 1000000000LL;
        sec -= 1;
    }
    t.tv_sec = sec;
    t.tv_nsec = nsec;
}

// Rewrite IPs/ports of a packet to match a target five-tuple. Recompute checksums/lengths.
static std::unique_ptr<pcpp::Packet> rewriteTuple(const pcpp::RawPacket &srcPacket,
                                                  const FlowKey &targetTuple) {
    auto pkt = std::make_unique<pcpp::Packet>(const_cast<pcpp::RawPacket *>(&srcPacket));
    if (targetTuple.ipVersion == 4) {
        if (auto *ip4 = pkt->getLayerOfType<pcpp::IPv4Layer>(); ip4 != nullptr) {
            ip4->setSrcIPv4Address(pcpp::IPv4Address(targetTuple.srcIp));
            ip4->setDstIPv4Address(pcpp::IPv4Address(targetTuple.dstIp));
        }
    } else {
        if (auto *ip6 = pkt->getLayerOfType<pcpp::IPv6Layer>(); ip6 != nullptr) {
            ip6->setSrcIPv6Address(pcpp::IPv6Address(targetTuple.srcIp));
            ip6->setDstIPv6Address(pcpp::IPv6Address(targetTuple.dstIp));
        }
    }

    if (auto *tcp = pkt->getLayerOfType<pcpp::TcpLayer>(); tcp != nullptr) {
        tcp->getTcpHeader()->portSrc = htons(targetTuple.srcPort);
        tcp->getTcpHeader()->portDst = htons(targetTuple.dstPort);
    } else if (auto *udp = pkt->getLayerOfType<pcpp::UdpLayer>(); udp != nullptr) {
        udp->getUdpHeader()->portSrc = htons(targetTuple.srcPort);
        udp->getUdpHeader()->portDst = htons(targetTuple.dstPort);
    }

    pkt->computeCalculateFields();
    return pkt;
}

// Determine if a packet is in the oriented A->B direction (A == targetTuple.src)
static bool isPacketDirA(const pcpp::Packet &pkt, const FlowKey &targetTuple) {
    if (targetTuple.ipVersion == 4) {
        auto *ip4 = pkt.getLayerOfType<pcpp::IPv4Layer>();
        if (ip4 == nullptr) return false;
        std::string s = ip4->getSrcIPAddress().toString();
        if (s != targetTuple.srcIp) return false;
        auto *tcp = pkt.getLayerOfType<pcpp::TcpLayer>();
        auto *udp = pkt.getLayerOfType<pcpp::UdpLayer>();
        if (tcp) return ntohs(tcp->getTcpHeader()->portSrc) == targetTuple.srcPort;
        if (udp) return ntohs(udp->getUdpHeader()->portSrc) == targetTuple.srcPort;
        return true;
    } else {
        auto *ip6 = pkt.getLayerOfType<pcpp::IPv6Layer>();
        if (ip6 == nullptr) return false;
        std::string s = ip6->getSrcIPAddress().toString();
        if (s != targetTuple.srcIp) return false;
        auto *tcp = pkt.getLayerOfType<pcpp::TcpLayer>();
        auto *udp = pkt.getLayerOfType<pcpp::UdpLayer>();
        if (tcp) return ntohs(tcp->getTcpHeader()->portSrc) == targetTuple.srcPort;
        if (udp) return ntohs(udp->getUdpHeader()->portSrc) == targetTuple.srcPort;
        return true;
    }
}

static uint32_t add32(uint32_t a, uint32_t b) { return a + b; }

int main(int argc, char *argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <substitution_pcap> <target_pcap> <output_pcapng>\n";
        std::cerr << "Notes:\n";
        std::cerr << " - This tool replaces the first 3 packets of each target flow with the first 6 packets\n";
        std::cerr << "   of a matching substitution flow. Exact 5-tuple match preferred; falls back to IP+protocol\n";
        std::cerr << "   with header rewrite (IPs/ports) if needed. Checksums are recalculated.\n";
        std::cerr << " - TCP sequence/ack continuity is not guaranteed when substituting from a different flow.\n";
        return 1;
    }

    std::string substitutionPath = argv[1];
    std::string targetPath = argv[2];
    std::string outputPath = argv[3];

    try {
        std::unordered_map<FlowKey, FlowPackets> subsBy5t;
        std::unordered_map<IpProtoKey, std::vector<FlowPackets *>> subsByIpProto;
        splitFileIntoFlows(substitutionPath, subsBy5t, subsByIpProto);

        std::unordered_map<FlowKey, FlowPackets> tgtBy5t;
        std::unordered_map<IpProtoKey, std::vector<FlowPackets *>> tgtByIpProto; // unused but keep signature aligned
        splitFileIntoFlows(targetPath, tgtBy5t, tgtByIpProto);
        // Build a list of all substitution flows for random fallback
        std::vector<FlowPackets *> subsAll;
        subsAll.reserve(subsBy5t.size());
        for (auto &kv2 : subsBy5t) subsAll.push_back(&kv2.second);

        std::vector<OutputPacketRef> allOut;
        allOut.reserve(1024);
        std::vector<std::unique_ptr<pcpp::Packet>> ownedPackets; // to keep rewritten packets alive
        ownedPackets.reserve(1024);

        size_t numFlows = 0, numExact = 0, numFallback = 0, numRandom = 0, numUnchanged = 0;

        for (const auto &kv : tgtBy5t) {
            numFlows++;
            const FlowKey &tKeyNormalized = kv.first;
            const FlowPackets &tFlow = kv.second;
            if (tFlow.empty()) continue;
            // Requirement: if original flow has only one packet, skip substitution
            if (tFlow.size() == 1) {
                numUnchanged++;
                for (const auto &rp : tFlow) {
                    OutputPacketRef ref{rp};
                    allOut.emplace_back(ref);
                }
                continue;
            }

            // Oriented target tuple from first packet for rewrite
            FlowKey tOriented{};
            IpProtoKey dummy{};
            (void)extractFlowKey(tFlow.front(), tOriented, dummy);
            FlowKey tNorm = normalizeFlowKey(tOriented);

            // Find substitution candidate (by normalized keys)
            const FlowPackets *subFlow = nullptr;
            auto itExact = subsBy5t.find(tNorm);
            if (itExact != subsBy5t.end()) {
                subFlow = &itExact->second;
                numExact++;
            } else {
                IpProtoKey k{tOriented.srcIp, tOriented.dstIp, tOriented.protocol, tOriented.ipVersion};
                IpProtoKey kNorm = normalizeIpProtoKey(k);
                auto itIp = subsByIpProto.find(kNorm);
                if (itIp != subsByIpProto.end() && !itIp->second.empty()) {
                    subFlow = itIp->second.front();
                    numFallback++;
                } else if (!subsAll.empty()) {
                    // Deterministic random selection based on normalized key hash
                    size_t idx = std::hash<FlowKey>{}(tNorm) % subsAll.size();
                    subFlow = subsAll[idx];
                    numRandom++;
                }
            }

            // Determine timestamps for alignment
            timespec t0 = tFlow.front().getPacketTimeStamp();
            timespec t3 = tFlow.size() > 3 ? tFlow[3].getPacketTimeStamp()
                                           : tFlow.back().getPacketTimeStamp();

            // Prepare inserted packets (up to 6)
            std::vector<pcpp::RawPacket> inserted;
            if (subFlow != nullptr && !subFlow->empty()) {
                size_t take = std::min<size_t>(6, subFlow->size());
                inserted.reserve(take);
                // Always rewrite to target oriented tuple to keep headers consistent
                for (size_t i = 0; i < take; ++i) {
                    auto rewritten = rewriteTuple((*subFlow)[i], tOriented);
                    pcpp::RawPacket *rp = rewritten->getRawPacket();
                    ownedPackets.emplace_back(std::move(rewritten));
                    inserted.emplace_back(*rp);
                }

                // TCP seq/ack normalization to align with first tail packet
                if (!inserted.empty() && tOriented.protocol == pcpp::IPProtocolTypes::PACKETPP_IPPROTO_TCP) {
                    // Compute next expected seq after inserted for each direction
                    bool haveA = false, haveB = false;
                    uint32_t nextSeqAfterA = 0, nextSeqAfterB = 0;
                    for (auto &rp : inserted) {
                        pcpp::Packet pkt(&rp);
                        auto *tcp = pkt.getLayerOfType<pcpp::TcpLayer>();
                        if (!tcp) continue;
                        uint32_t seq = ntohl(tcp->getTcpHeader()->sequenceNumber);
                        size_t payloadLen = tcp->getLayerPayloadSize();
                        uint32_t advance = static_cast<uint32_t>(payloadLen);
                        if (tcp->getTcpHeader()->synFlag) advance += 1;
                        if (tcp->getTcpHeader()->finFlag) advance += 1;
                        uint32_t endSeq = seq + advance;
                        if (isPacketDirA(pkt, tOriented)) {
                            if (!haveA) { haveA = true; nextSeqAfterA = endSeq; }
                            else { nextSeqAfterA = std::max(nextSeqAfterA, endSeq); }
                        } else {
                            if (!haveB) { haveB = true; nextSeqAfterB = endSeq; }
                            else { nextSeqAfterB = std::max(nextSeqAfterB, endSeq); }
                        }
                    }

                    // Extract target next expected seq from tail acks
                    uint32_t targetNextA = 0, targetNextB = 0;
                    bool haveTargetA = false, haveTargetB = false;
                    for (size_t i = 0; i < tFlow.size(); ++i) {
                        if (i < 3) continue; // tail only
                        pcpp::Packet tpkt(const_cast<pcpp::RawPacket *>(&tFlow[i]));
                        auto *tcp = tpkt.getLayerOfType<pcpp::TcpLayer>();
                        if (!tcp) continue;
                        uint32_t ack = ntohl(tcp->getTcpHeader()->ackNumber);
                        if (isPacketDirA(tpkt, tOriented)) {
                            // A->B packet acknowledges B
                            if (!haveTargetB) { haveTargetB = true; targetNextB = ack; }
                        } else {
                            // B->A packet acknowledges A
                            if (!haveTargetA) { haveTargetA = true; targetNextA = ack; }
                        }
                        if (haveTargetA && haveTargetB) break;
                    }

                    uint32_t deltaA = 0, deltaB = 0;
                    if (haveA && haveTargetA) {
                        deltaA = targetNextA - nextSeqAfterA; // modulo-32
                    }
                    if (haveB && haveTargetB) {
                        deltaB = targetNextB - nextSeqAfterB; // modulo-32
                    }

                    // Apply deltas to inserted packets
                    if (deltaA != 0 || deltaB != 0) {
                        for (auto &rp : inserted) {
                            pcpp::Packet pkt(&rp);
                            auto *tcp = pkt.getLayerOfType<pcpp::TcpLayer>();
                            if (!tcp) continue;
                            bool dirA = isPacketDirA(pkt, tOriented);
                            uint32_t seq = ntohl(tcp->getTcpHeader()->sequenceNumber);
                            uint32_t ack = ntohl(tcp->getTcpHeader()->ackNumber);
                            if (dirA) {
                                seq = add32(seq, deltaA);
                                ack = add32(ack, deltaB);
                            } else {
                                seq = add32(seq, deltaB);
                                ack = add32(ack, deltaA);
                            }
                            tcp->getTcpHeader()->sequenceNumber = htonl(seq);
                            tcp->getTcpHeader()->ackNumber = htonl(ack);
                            pkt.computeCalculateFields();
                        }
                    }
                }
            }

            // Adjust timestamps: place inserted packets starting at t0 with 1ms increments
            const int64_t stepNs = 1'000'000; // 1 ms
            timespec cur = t0;
            for (auto &rp : inserted) {
                rp.setPacketTimeStamp(cur);
                addNanos(cur, stepNs);
            }

            // Determine shift needed for remaining target packets so that packet index 3 (or next) occurs after inserted
            timespec lastInserted = inserted.empty() ? t0 : inserted.back().getPacketTimeStamp();
            // Ensure next target packet timestamp is strictly after lastInserted
            int64_t epsilon = 1'000; // 1 microsecond
            addNanos(lastInserted, epsilon);

            // Build tail of the target flow starting from packet index 3 (drop first 3)
            std::vector<pcpp::RawPacket> tail;
            if (tFlow.size() > 3) {
                tail.reserve(tFlow.size() - 3);
                for (size_t i = 3; i < tFlow.size(); ++i) {
                    tail.emplace_back(tFlow[i]);
                }
                // Compute shift: move first tail packet from original t3 to lastInserted
                timespec origFirstTail = t3;
                // shift = lastInserted - origFirstTail
                int64_t dsec = lastInserted.tv_sec - origFirstTail.tv_sec;
                int64_t dnsec = lastInserted.tv_nsec - origFirstTail.tv_nsec;
                for (auto &rp : tail) {
                    timespec ts = rp.getPacketTimeStamp();
                    ts.tv_sec += dsec;
                    ts.tv_nsec += dnsec;
                    // normalize
                    if (ts.tv_nsec >= 1000000000L) {
                        ts.tv_sec += 1;
                        ts.tv_nsec -= 1000000000L;
                    } else if (ts.tv_nsec < 0) {
                        ts.tv_sec -= 1;
                        ts.tv_nsec += 1000000000L;
                    }
                    rp.setPacketTimeStamp(ts);
                }
            }

            // If no substitution found, keep original flow unchanged
            if (inserted.empty()) {
                numUnchanged++;
                for (const auto &rp : tFlow) {
                    OutputPacketRef ref{rp};
                    allOut.emplace_back(ref);
                }
            } else {
                for (auto &rp : inserted) {
                    OutputPacketRef ref{rp};
                    allOut.emplace_back(ref);
                }
                for (auto &rp : tail) {
                    OutputPacketRef ref{rp};
                    allOut.emplace_back(ref);
                }
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
        std::cout << " - Exact 5-tuple substitutions: " << numExact << "\n";
        std::cout << " - IP+protocol substitutions (with header rewrite): " << numFallback << "\n";
        std::cout << " - Random substitutions (no match found): " << numRandom << "\n";
        std::cout << " - Flows left unchanged (no candidate): " << numUnchanged << "\n";
        std::cout << "Output written to: " << outputPath << std::endl;
    } catch (const std::exception &ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}


