#include "PcapFileDevice.h"
#include "Packet.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include <iostream>
#include <string>
#include <set>

int main(int argc, char *argv[]) {
    if (argc < 3 or argc > 4) {
        std::cerr << "Usage: " << argv[0] << " <inputfile> <outputfile> [optional: <unixtime_seconds to set as a start of the file>]\n";
        return 1;
    }

    auto *reader = pcpp::IFileReaderDevice::getReader(argv[1]);

    if (reader == nullptr) {
        std::cerr << "Cannot determine reader for file: " << argv[1] << std::endl;
        return 1;
    }
    if (!reader->open()) {
        std::cerr << "Cannot open " << argv[1] << " for reading" << std::endl;
        return 1;
    }


    std::string outFileName = argv[2];
    pcpp::IFileWriterDevice *writer;
    if (outFileName.ends_with(".pcap")) {
        writer = new pcpp::PcapFileWriterDevice(argv[2]);
    } else if (outFileName.ends_with(".pcapng")) {
        writer = new pcpp::PcapNgFileWriterDevice(argv[2]);
    } else {
        std::cerr << "Output file must have .pcap or .pcapng extension" << std::endl;
        return 1;
    }

    // Delay opening the writer until we know the input link-layer type for the first packet we actually intend to write.
    bool writerOpened = false;
    bool writerIsPcap = outFileName.ends_with(".pcap");
    pcpp::LinkLayerType selectedLinkLayer = pcpp::LINKTYPE_INVALID;

    // parse the optional argument
    bool enable_time_shift = false;
    long unixtime_seconds = 0;
    if (argc == 4) {
        unixtime_seconds = std::stol(argv[3]);
        enable_time_shift = true;
    }

    long diff = 0;
    bool first = true;

    // Set to store unique IP addresses
    std::set<std::string> uniqueIPs;

    pcpp::RawPacket rawPacket;
    while (reader->getNextPacket(rawPacket)) {
        if (enable_time_shift) {
            if (first) {
                first = false;
                diff = rawPacket.getPacketTimeStamp().tv_sec - unixtime_seconds;
            } else {
                auto x = rawPacket.getPacketTimeStamp();
                x.tv_sec -= diff;
                rawPacket.setPacketTimeStamp(x);
            }
        }

        pcpp::Packet parsedPacket(&rawPacket);
        bool isIPv4 = parsedPacket.isPacketOfType(pcpp::IPv4);
        bool isIPv6 = parsedPacket.isPacketOfType(pcpp::IPv6);
        if (isIPv4 || isIPv6) {
            if (parsedPacket.isPacketOfType(pcpp::TCP) ||
                parsedPacket.isPacketOfType(pcpp::UDP) ||
                parsedPacket.isPacketOfType(pcpp::ICMP)) {

                pcpp::LinkLayerType current_link_layer = rawPacket.getLinkLayerType();
                // std::cout << " - Current link layer: " << current_link_layer << std::endl;

                if (!writerOpened) {
                    if (writerIsPcap) {
                        selectedLinkLayer = current_link_layer;
                        auto *pcapWriter = dynamic_cast<pcpp::PcapFileWriterDevice *>(writer);
                        if (pcapWriter == nullptr) {
                            std::cerr << "Internal error: writer type mismatch for .pcap" << std::endl;
                            reader->close();
                            delete writer;
                            return 1;
                        }
                        if (!pcapWriter->open(selectedLinkLayer)) {
                            std::cerr << "Error opening output file with link-layer " << selectedLinkLayer
                                      << ": " << argv[2] << std::endl;
                            reader->close();
                            delete writer;
                            return 1;
                        }
                        std::cerr << "Opened .pcap writer with link-layer: " << selectedLinkLayer << std::endl;
                    } else {
                        if (!writer->open()) {
                            std::cerr << "Error opening output file: " << argv[2] << std::endl;
                            reader->close();
                            delete writer;
                            return 1;
                        }
                        std::cerr << "Opened .pcapng writer" << std::endl;
                    }
                    writerOpened = true;
                }

                if (writerIsPcap && current_link_layer != selectedLinkLayer) {
                    std::cerr << "Skipping packet: link-layer mismatch (packet=" << current_link_layer
                              << ", file=" << selectedLinkLayer << ")" << std::endl;
                    continue;
                }

                writer->writePacket(rawPacket);

                // Extract and store IP addresses from successfully written packets
                if (isIPv4) {
                    pcpp::IPv4Layer* ipv4Layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
                    if (ipv4Layer != nullptr) {
                        uniqueIPs.insert(ipv4Layer->getSrcIPAddress().toString());
                        uniqueIPs.insert(ipv4Layer->getDstIPAddress().toString());
                    }
                } else if (isIPv6) {
                    pcpp::IPv6Layer* ipv6Layer = parsedPacket.getLayerOfType<pcpp::IPv6Layer>();
                    if (ipv6Layer != nullptr) {
                        uniqueIPs.insert(ipv6Layer->getSrcIPAddress().toString());
                        uniqueIPs.insert(ipv6Layer->getDstIPAddress().toString());
                    }
                }
            }
        }
    }

    reader->close();
    if (writerOpened) {
        writer->close();
    }

    // Print unique IP addresses
    std::cout << "\n=== Unique IP Addresses in Filtered File ===" << std::endl;
    std::cout << "Total unique IP addresses: " << uniqueIPs.size() << std::endl;
    std::cout << "IP addresses:" << std::endl;
    for (const auto& ip : uniqueIPs) {
        std::cout << "  " << ip << std::endl;
    }
    std::cout << "===========================================" << std::endl;

    return 0;
}


