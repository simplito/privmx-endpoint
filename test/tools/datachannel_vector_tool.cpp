#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <privmx/endpoint/core/Buffer.hpp>
#include <privmx/endpoint/stream/Types.hpp>
#include <privmx/endpoint/stream/WebRTCInterface.hpp>
#include <privmx/endpoint/stream/encryptors/dataChannel/DataChannelMessageEncryptorV1.hpp>

// Standalone golden-vector tool for cross-checking the encrypted DataChannel
//
// Usage:
//   datachannel_vector_tool enc <hexKey32B> <keyId> <seq> <plaintextUtf8>
//   datachannel_vector_tool dec <hexKey32B> <keyId> <hexFrame>

using namespace privmx::endpoint;
using namespace privmx::endpoint::stream;

namespace {

std::vector<uint8_t> hexToBytes(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::runtime_error("hex string must have even length");
    }
    std::vector<uint8_t> out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<uint8_t>(std::stoul(hex.substr(i * 2, 2), nullptr, 16));
    }
    return out;
}

std::string bytesToHex(const std::string& data) {
    static const char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (unsigned char c : data) {
        out.push_back(digits[c >> 4]);
        out.push_back(digits[c & 0xF]);
    }
    return out;
}

std::string bytesToString(const std::vector<uint8_t>& bytes) {
    return std::string(bytes.begin(), bytes.end());
}

void printUsage() {
    std::cerr << "Usage:\n"
                 "  datachannel_vector_tool enc <hexKey32B> <keyId> <seq> <plaintextUtf8>\n"
                 "  datachannel_vector_tool dec <hexKey32B> <keyId> <hexFrame> [hexFrame...]\n"
                 "\n"
                 "dec accepts multiple frames decrypted in order on a single encryptor\n"
                 "instance (one SEQ=.. line per frame), so replay protection can be\n"
                 "exercised by passing an already-seen/lower sequence number twice.\n";
}

} // namespace

int main(int argc, char** argv) {
    std::vector<std::string> args(argv + 1, argv + argc);
    if (args.size() < 4) {
        printUsage();
        return 2;
    }

    try {
        const std::string& mode = args.at(0);
        auto keyBytes = hexToBytes(args.at(1));
        const std::string& keyId = args.at(2);
        Key key{keyId, core::Buffer::from(bytesToString(keyBytes)), KeyType::LOCAL};
        DataChannelMessageEncryptorV1 encryptor({key});

        if (mode == "enc") {
            if (args.size() < 5) {
                printUsage();
                return 2;
            }
            uint32_t seq = static_cast<uint32_t>(std::stoul(args.at(3)));
            const std::string& plaintext = args.at(4);
            DataChannelMessage msg{core::Buffer::from(plaintext), static_cast<int64_t>(seq)};
            core::Buffer frame = encryptor.encryptMessage(msg);
            std::cout << bytesToHex(frame.stdString()) << std::endl;
            return 0;
        }

        if (mode == "dec") {
            for (size_t i = 3; i < args.size(); ++i) {
                auto frameBytes = hexToBytes(args.at(i));
                core::Buffer frame = core::Buffer::from(bytesToString(frameBytes));
                DecryptedDataChannelMessage result = encryptor.decryptMessage("test", frame);
                std::cout << "SEQ=" << result.seq << " STATUS=" << result.statusCode
                           << " DATA=" << result.data.stdString() << std::endl;
            }
            return 0;
        }

        std::cerr << "Unknown mode: " << mode << std::endl;
        printUsage();
        return 2;
    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
        return 1;
    }
}
