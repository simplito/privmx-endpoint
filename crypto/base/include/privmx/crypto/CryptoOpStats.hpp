/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTO_CRYPTOOPSTATS_HPP_
#define _PRIVMXLIB_CRYPTO_CRYPTOOPSTATS_HPP_

#include <array>
#include <atomic>
#include <cstdint>
#include <string>

namespace privmx {
namespace crypto {

/**
 * ⚠️ EPHEMERAL — BENCHMARK INSTRUMENTATION, NOT FOR MERGE.
 *
 * Counts primitive crypto operations, so a benchmark can report the cost of a protocol operation in something more
 * meaningful than wall-clock time: machine speed varies, operation counts are a property of the design.
 *
 * Counted at the primitive level rather than at the level of a "wrap", because the primitives have costs that
 * differ by three orders of magnitude — an ECDSA verify is not comparable to an HMAC — and because a wrap's
 * composition is exactly the thing worth seeing. The three classes are kept apart in every report:
 *
 *   - **asymmetric** (keygen, ECDH, sign, verify) — hundreds of microseconds each; these decide the cost
 *   - **symmetric** (AES, HMAC, hashes, KDF) — microseconds; visible only in bulk
 *   - **randomness** — cheap, but a useful sanity check on how many fresh secrets an operation mints
 *
 * One relaxed atomic increment per crypto call: noise next to an EC operation, measurable next to a hash. This
 * whole header should be reverted along with its call sites once the measurements are taken.
 */
class CryptoOpStats {
public:
    /** Every primitive counted. Order matters: it drives the report's column order. */
    enum class Op : std::size_t {
        // asymmetric
        Keygen = 0,
        Ecdh,
        Sign,
        Verify,
        // symmetric — bulk
        AesEncrypt,
        AesDecrypt,
        // symmetric — small
        Hmac,
        Sha256,
        Sha512,
        OtherHash,
        Kdf,
        // entropy
        RandomBytes,
        Count,
    };

    static constexpr std::size_t OpCount = static_cast<std::size_t>(Op::Count);

    static const char* name(Op op) {
        switch (op) {
            case Op::Keygen: return "keygen";
            case Op::Ecdh: return "ECDH";
            case Op::Sign: return "sign";
            case Op::Verify: return "verify";
            case Op::AesEncrypt: return "AES-enc";
            case Op::AesDecrypt: return "AES-dec";
            case Op::Hmac: return "HMAC";
            case Op::Sha256: return "SHA-256";
            case Op::Sha512: return "SHA-512";
            case Op::OtherHash: return "hash-oth";
            case Op::Kdf: return "KDF";
            case Op::RandomBytes: return "random";
            default: return "?";
        }
    }

    /** Whether the primitive is an elliptic-curve operation, i.e. one that actually costs. */
    static bool isAsymmetric(Op op) {
        return op == Op::Keygen || op == Op::Ecdh || op == Op::Sign || op == Op::Verify;
    }

    struct Snapshot {
        std::array<std::uint64_t, OpCount> counts{};

        std::uint64_t get(Op op) const { return counts[static_cast<std::size_t>(op)]; }

        std::uint64_t asymmetric() const {
            std::uint64_t sum = 0;
            for (std::size_t i = 0; i < OpCount; ++i) {
                if (isAsymmetric(static_cast<Op>(i))) {
                    sum += counts[i];
                }
            }
            return sum;
        }

        std::uint64_t symmetric() const {
            std::uint64_t sum = 0;
            for (std::size_t i = 0; i < OpCount; ++i) {
                const Op op = static_cast<Op>(i);
                if (!isAsymmetric(op) && op != Op::RandomBytes) {
                    sum += counts[i];
                }
            }
            return sum;
        }

        std::uint64_t total() const { return asymmetric() + symmetric() + get(Op::RandomBytes); }

        bool empty() const { return total() == 0; }
    };

    static void count(Op op) {
        counters()[static_cast<std::size_t>(op)].fetch_add(1, std::memory_order_relaxed);
    }

    static Snapshot read() {
        Snapshot snapshot;
        for (std::size_t i = 0; i < OpCount; ++i) {
            snapshot.counts[i] = counters()[i].load(std::memory_order_relaxed);
        }
        return snapshot;
    }

    /** Difference between two snapshots, so one operation can be measured inside a long-running process. */
    static Snapshot since(const Snapshot& before) {
        Snapshot now = read();
        for (std::size_t i = 0; i < OpCount; ++i) {
            now.counts[i] -= before.counts[i];
        }
        return now;
    }

private:
    static std::array<std::atomic<std::uint64_t>, OpCount>& counters() {
        static std::array<std::atomic<std::uint64_t>, OpCount> instance{};
        return instance;
    }
};

} // namespace crypto
} // namespace privmx

#endif // _PRIVMXLIB_CRYPTO_CRYPTOOPSTATS_HPP_
