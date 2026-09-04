#include "privmx/endpoint/group/encryptors/envelope/GroupEnvelopeEncryptor.hpp"

#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/EciesEncryptor.hpp>
#include <privmx/endpoint/core/CoreException.hpp>

#include "privmx/endpoint/group/GroupException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::group;

/**
 * Domain separator on the ECIES plaintext of a type 2 envelope. Load-bearing.
 *
 * The epoch ladder wraps a *previous epoch's grant private key* to the group's grant public key with
 * `EciesEncryptor` — see `TreeKeys::wrapKey`. Those rungs are therefore byte-identical in construction to a
 * type 2 key wrap and addressed to the very same key. Without a marker distinguishing the two, an attacker
 * could lift a rung off the wire, present it as a type 2 envelope, and have `openAnonymousEnvelope` resolve
 * the grant key, unwrap it and hand back a past private key as "message content" — walking straight past the
 * era-floor, pruning and registry checks that `LadderKeys` exists to enforce.
 *
 * Requiring this prefix closes it: a rung's plaintext is a WIF and can never carry it.
 */
const std::string GroupEnvelopeEncryptor::ECIES_DOMAIN = "PMXENV1";

namespace {

constexpr Poco::UInt8 TYPE_GROUP_KEY = 1;
constexpr Poco::UInt8 TYPE_ANONYMOUS = 2;
constexpr Poco::UInt8 TYPE_FILE = 3;
constexpr Poco::UInt8 TYPE_ANON_FILE = 4;

constexpr std::size_t CONTENT_KEY_SIZE = 32;

// Hand-rolled rather than `utils::BinaryBufferBE`: that helper leaves its length octet *uninitialized* when
// the stream is already at EOF and its `readRaw` returns a short string without complaint, so a three-byte
// envelope "parses" into garbage. Every read here is bounds-checked against the real buffer instead.
class Cursor {
public:
    Cursor(const std::string& buf) : _buf(buf) {}

    Poco::UInt8 readU8() {
        require(1);
        return static_cast<Poco::UInt8>(_buf[_pos++]);
    }

    Poco::UInt64 readU64() {
        require(8);
        Poco::UInt64 value = 0;
        for (int i = 0; i < 8; ++i) {
            value = (value << 8) | static_cast<Poco::UInt8>(_buf[_pos++]);
        }
        return value;
    }

    std::string readField() {
        std::size_t len = readU8();
        require(len);
        std::string value = _buf.substr(_pos, len);
        _pos += len;
        return value;
    }

    std::string readRest() {
        std::string value = _buf.substr(_pos);
        _pos = _buf.size();
        return value;
    }

    /** Bytes consumed so far — i.e. the header, once the header fields have been read. */
    std::string consumed() const { return _buf.substr(0, _pos); }

    void requireEnd() const {
        if (_pos != _buf.size()) {
            throw InvalidEnvelopeFormatException("trailing bytes after envelope payload");
        }
    }

private:
    void require(std::size_t n) const {
        if (_buf.size() - _pos < n) {
            throw InvalidEnvelopeFormatException("envelope truncated");
        }
    }

    const std::string& _buf;
    std::size_t _pos = 0;
};

void putField(std::string& out, const std::string& value) {
    if (value.size() > 255) {
        // The wire uses a single length octet, and a silent truncation here would produce an envelope that
        // parses cleanly into the wrong thing. Real fields are far below this (`groupId` is capped at 128 by
        // `Validator::validateId`, `keyId` is 32 hex chars, a DER public key is 33 bytes).
        throw InvalidEnvelopeFormatException("envelope field exceeds 255 bytes");
    }
    out.push_back(static_cast<char>(value.size()));
    out.append(value);
}

std::string toBE(Poco::UInt64 value, int bytes) {
    std::string out(bytes, '\0');
    for (int i = bytes - 1; i >= 0; --i) {
        out[i] = static_cast<char>(value & 0xFF);
        value >>= 8;
    }
    return out;
}

} // namespace

std::string GroupEnvelopeEncryptor::writeHeader(Poco::UInt8 type, const std::vector<std::string>& fields) {
    std::string header;
    header.push_back(static_cast<char>(VERSION));
    header.push_back(static_cast<char>(type));
    for (const std::string& field : fields) {
        putField(header, field);
    }
    return header;
}

std::string GroupEnvelopeEncryptor::chunkKey(const std::string& fileKey, ChunkIndex index) {
    // Binding the index into the key is what makes a chunk unusable in any other position, and binding the
    // per-file random key is what makes it unusable in any other file.
    return privmx::crypto::Crypto::sha256(fileKey + toBE(index, 4));
}

std::pair<std::string, std::string> GroupEnvelopeEncryptor::wrapContentKey(
    const privmx::crypto::PublicKey& groupPubKey
) {
    // Throwaway, never retained: it exists only to carry out one ECDH with the group's identity key.
    privmx::crypto::PrivateKey ephemeralPrivKey = privmx::crypto::PrivateKey::generateRandom();
    std::string contentKey = privmx::crypto::Crypto::randomBytes(CONTENT_KEY_SIZE);
    std::string wrap =
        privmx::crypto::EciesEncryptor::encrypt(groupPubKey, ECIES_DOMAIN + contentKey, ephemeralPrivKey);
    return {wrap, contentKey};
}

std::string GroupEnvelopeEncryptor::unwrapContentKey(
    const privmx::crypto::PrivateKey& groupPrivKey,
    const std::string& groupPubKeyBase58,
    const std::string& wrap
) {
    // The key we resolved must be the key the envelope names. Otherwise a hostile server could steer us onto
    // some other epoch's key and leave the ECIES 4-byte checksum as the only thing standing between us and a
    // wrong answer.
    if (groupPrivKey.getPublicKey() != privmx::crypto::PublicKey::fromBase58DER(groupPubKeyBase58)) {
        throw InvalidEnvelopeFormatException("resolved group key does not match the key named by the envelope");
    }
    std::string unwrapped = privmx::crypto::EciesEncryptor::decrypt(groupPrivKey, wrap);
    if (unwrapped.rfind(ECIES_DOMAIN, 0) != 0 || unwrapped.size() != ECIES_DOMAIN.size() + CONTENT_KEY_SIZE) {
        // Not one of ours. Most importantly: an epoch-ladder rung, which is the same ECIES construction
        // addressed to the same key but carries a grant private key. See ECIES_DOMAIN above.
        throw InvalidEnvelopeFormatException("wrapped key is not a group envelope key");
    }
    return unwrapped.substr(ECIES_DOMAIN.size());
}

// -- type 1 --------------------------------------------------------------------------------------------

core::Buffer GroupEnvelopeEncryptor::packGroupKeyEnvelope(
    const std::string& groupId,
    const std::string& keyId,
    const core::Buffer& content,
    const privmx::crypto::PrivateKey& authorPrivKey,
    const std::string& groupKey
) {
    std::string header =
        writeHeader(TYPE_GROUP_KEY, {groupId, keyId, authorPrivKey.getPublicKey().toDER()});
    core::Buffer signed_ = _dataEncryptor.signAndPackDataWithSignature(
        core::Buffer::from(header + content.stdString()), authorPrivKey
    );
    return core::Buffer::from(header + _dataEncryptor.encrypt(signed_, groupKey).stdString());
}

DecryptedEnvelope GroupEnvelopeEncryptor::openGroupKeyEnvelope(
    const core::Buffer& envelope,
    const std::string& groupKey
) {
    Cursor cursor(envelope.stdString());
    if (cursor.readU8() != VERSION) {
        throw InvalidEnvelopeFormatException("unsupported envelope version");
    }
    if (cursor.readU8() != TYPE_GROUP_KEY) {
        throw InvalidEnvelopeFormatException("not a group-key envelope");
    }
    std::string groupId = cursor.readField();
    cursor.readField(); // keyId — the caller already used it to pick `groupKey`
    std::string authorPubKeyDer = cursor.readField();
    std::string header = cursor.consumed();

    privmx::crypto::PublicKey authorPubKey = privmx::crypto::PublicKey::fromDER(authorPubKeyDer);
    core::Buffer plain = _dataEncryptor.verifyAndExtractData(
        _dataEncryptor.decrypt(core::Buffer::from(cursor.readRest()), groupKey), authorPubKey
    );
    // The header the author signed must be the header we were served. Anything else is a rewrite: another
    // group's id, another key, another author, or a file header relabelled as a message.
    if (plain.stdString().rfind(header, 0) != 0) {
        throw InvalidEnvelopeFormatException("envelope header does not match the signed header");
    }
    return DecryptedEnvelope{
        .data = core::Buffer::from(plain.stdString().substr(header.size())),
        .groupId = groupId,
        .authorPubKey = authorPubKey.toBase58DER(),
        .type = ENVELOPE_FROM_MEMBER,
    };
}

// -- type 2 --------------------------------------------------------------------------------------------

core::Buffer GroupEnvelopeEncryptor::packAnonymousEnvelope(
    const std::string& groupId,
    const privmx::crypto::PublicKey& groupPubKey,
    const core::Buffer& content
) {
    auto [wrap, contentKey] = wrapContentKey(groupPubKey);
    std::string header = writeHeader(TYPE_ANONYMOUS, {groupId, groupPubKey.toBase58DER()});

    std::string out = header;
    putField(out, wrap);
    // No author signature: the sender is anonymous by construction, so a signature by the throwaway key would
    // attest to nothing. The header is authenticated by being inside this encrypt-then-MAC payload.
    out.append(_dataEncryptor.encrypt(core::Buffer::from(header + content.stdString()), contentKey).stdString());
    return core::Buffer::from(out);
}

DecryptedEnvelope GroupEnvelopeEncryptor::openAnonymousEnvelope(
    const core::Buffer& envelope,
    const privmx::crypto::PrivateKey& groupPrivKey
) {
    Cursor cursor(envelope.stdString());
    if (cursor.readU8() != VERSION) {
        throw InvalidEnvelopeFormatException("unsupported envelope version");
    }
    if (cursor.readU8() != TYPE_ANONYMOUS) {
        throw InvalidEnvelopeFormatException("not an anonymous envelope");
    }
    std::string groupId = cursor.readField();
    std::string groupPubKeyBase58 = cursor.readField();
    std::string header = cursor.consumed();
    std::string wrap = cursor.readField();

    std::string contentKey = unwrapContentKey(groupPrivKey, groupPubKeyBase58, wrap);

    core::Buffer plain = _dataEncryptor.decrypt(core::Buffer::from(cursor.readRest()), contentKey);
    if (plain.stdString().rfind(header, 0) != 0) {
        throw InvalidEnvelopeFormatException("envelope header does not match the sealed header");
    }
    return DecryptedEnvelope{
        .data = core::Buffer::from(plain.stdString().substr(header.size())),
        .groupId = groupId,
        // Deliberately empty: the throwaway sender key attests to nothing, so reporting it would invite
        // callers to treat it as an identity.
        .authorPubKey = std::string(),
        .type = ENVELOPE_ANONYMOUS,
    };
}

// -- type 3 --------------------------------------------------------------------------------------------

core::Buffer GroupEnvelopeEncryptor::packFileEnvelope(
    const std::string& groupId,
    const std::string& keyId,
    ByteCount plainSize,
    const std::string& fileKey,
    const privmx::crypto::PrivateKey& authorPrivKey,
    const std::string& groupKey
) {
    std::string header = writeHeader(TYPE_FILE, {groupId, keyId, authorPrivKey.getPublicKey().toDER()});
    // `plainSize` inside the signature is the only thing that makes a dropped trailing chunk detectable —
    // each chunk authenticates itself, but nothing about chunk N says how many were supposed to follow.
    std::string body = header + toBE(plainSize, 8) + fileKey;
    core::Buffer signed_ = _dataEncryptor.signAndPackDataWithSignature(core::Buffer::from(body), authorPrivKey);
    return core::Buffer::from(header + _dataEncryptor.encrypt(signed_, groupKey).stdString());
}

GroupEnvelopeEncryptor::FileHeader GroupEnvelopeEncryptor::unpackFileEnvelope(
    const core::Buffer& envelope,
    const std::string& groupKey
) {
    Cursor cursor(envelope.stdString());
    if (cursor.readU8() != VERSION) {
        throw InvalidEnvelopeFormatException("unsupported envelope version");
    }
    if (cursor.readU8() != TYPE_FILE) {
        throw InvalidEnvelopeFormatException("not a file envelope");
    }
    std::string groupId = cursor.readField();
    std::string keyId = cursor.readField();
    std::string authorPubKeyDer = cursor.readField();
    std::string header = cursor.consumed();

    privmx::crypto::PublicKey authorPubKey = privmx::crypto::PublicKey::fromDER(authorPubKeyDer);
    core::Buffer plain = _dataEncryptor.verifyAndExtractData(
        _dataEncryptor.decrypt(core::Buffer::from(cursor.readRest()), groupKey), authorPubKey
    );
    if (plain.stdString().rfind(header, 0) != 0) {
        throw InvalidEnvelopeFormatException("envelope header does not match the signed header");
    }

    Cursor inner(plain.stdString());
    for (std::size_t i = 0; i < header.size(); ++i) {
        inner.readU8();
    }
    ByteCount plainSize = inner.readU64();
    std::string fileKey = inner.readRest();
    if (fileKey.size() != CONTENT_KEY_SIZE) {
        throw InvalidEnvelopeFormatException("file envelope carries a malformed file key");
    }
    return FileHeader{
        .type = ENVELOPE_FROM_MEMBER,
        .groupId = groupId,
        .keyId = keyId,
        .authorPubKey = authorPubKey.toBase58DER(),
        .plainSize = plainSize,
        .fileKey = fileKey,
    };
}

// -- type 4 --------------------------------------------------------------------------------------------

core::Buffer GroupEnvelopeEncryptor::packAnonymousFileEnvelope(
    const std::string& groupId,
    const privmx::crypto::PublicKey& groupPubKey,
    ByteCount plainSize,
    const std::string& fileKey
) {
    auto [wrap, contentKey] = wrapContentKey(groupPubKey);
    std::string header = writeHeader(TYPE_ANON_FILE, {groupId, groupPubKey.toBase58DER()});

    std::string out = header;
    putField(out, wrap);
    // No signature, for the same reason as type 2: the sender is anonymous by construction. `plainSize` is
    // still covered — it sits inside this encrypt-then-MAC payload, so a dropped tail is detectable even
    // though its author is not.
    out.append(
        _dataEncryptor.encrypt(core::Buffer::from(header + toBE(plainSize, 8) + fileKey), contentKey).stdString()
    );
    return core::Buffer::from(out);
}

GroupEnvelopeEncryptor::FileHeader GroupEnvelopeEncryptor::unpackAnonymousFileEnvelope(
    const core::Buffer& envelope,
    const privmx::crypto::PrivateKey& groupPrivKey
) {
    Cursor cursor(envelope.stdString());
    if (cursor.readU8() != VERSION) {
        throw InvalidEnvelopeFormatException("unsupported envelope version");
    }
    if (cursor.readU8() != TYPE_ANON_FILE) {
        throw InvalidEnvelopeFormatException("not an anonymous file envelope");
    }
    std::string groupId = cursor.readField();
    std::string groupPubKeyBase58 = cursor.readField();
    std::string header = cursor.consumed();
    std::string wrap = cursor.readField();

    std::string contentKey = unwrapContentKey(groupPrivKey, groupPubKeyBase58, wrap);
    core::Buffer plain = _dataEncryptor.decrypt(core::Buffer::from(cursor.readRest()), contentKey);
    if (plain.stdString().rfind(header, 0) != 0) {
        throw InvalidEnvelopeFormatException("envelope header does not match the sealed header");
    }

    Cursor inner(plain.stdString());
    for (std::size_t i = 0; i < header.size(); ++i) {
        inner.readU8();
    }
    ByteCount plainSize = inner.readU64();
    std::string fileKey = inner.readRest();
    if (fileKey.size() != CONTENT_KEY_SIZE) {
        throw InvalidEnvelopeFormatException("file envelope carries a malformed file key");
    }
    return FileHeader{
        .type = ENVELOPE_ANONYMOUS,
        .groupId = groupId,
        .keyId = std::string(),
        // Deliberately empty: the throwaway sender key attests to nothing.
        .authorPubKey = std::string(),
        .plainSize = plainSize,
        .fileKey = fileKey,
    };
}

core::Buffer GroupEnvelopeEncryptor::encryptChunk(
    const core::Buffer& plainChunk,
    const std::string& fileKey,
    ChunkIndex index
) {
    return _dataEncryptor.encrypt(plainChunk, chunkKey(fileKey, index));
}

core::Buffer GroupEnvelopeEncryptor::decryptChunk(
    const core::Buffer& cipherChunk,
    const std::string& fileKey,
    ChunkIndex index
) {
    return _dataEncryptor.decrypt(cipherChunk, chunkKey(fileKey, index));
}

// -- dispatch ------------------------------------------------------------------------------------------

GroupEnvelopeEncryptor::Routing GroupEnvelopeEncryptor::peek(const core::Buffer& envelope) {
    Cursor cursor(envelope.stdString());
    if (cursor.readU8() != VERSION) {
        throw InvalidEnvelopeFormatException("unsupported envelope version");
    }
    Poco::UInt8 type = cursor.readU8();
    Routing routing;
    routing.groupId = cursor.readField();
    if (type == TYPE_GROUP_KEY) {
        routing.type = ENVELOPE_FROM_MEMBER;
        routing.keyId = cursor.readField();
    } else if (type == TYPE_ANONYMOUS) {
        routing.type = ENVELOPE_ANONYMOUS;
        routing.groupPubKey = cursor.readField();
    } else {
        // File types included: those open through `beginFileDecryption`, which knows to expect a body.
        // Letting one through here would mean handing back a file key as though it were message content.
        throw InvalidEnvelopeFormatException("unsupported envelope type");
    }
    return routing;
}

GroupEnvelopeEncryptor::Routing GroupEnvelopeEncryptor::peekFile(const core::Buffer& envelope) {
    Cursor cursor(envelope.stdString());
    if (cursor.readU8() != VERSION) {
        throw InvalidEnvelopeFormatException("unsupported envelope version");
    }
    Poco::UInt8 type = cursor.readU8();
    Routing routing;
    routing.groupId = cursor.readField();
    if (type == TYPE_FILE) {
        routing.type = ENVELOPE_FROM_MEMBER;
        routing.keyId = cursor.readField();
    } else if (type == TYPE_ANON_FILE) {
        routing.type = ENVELOPE_ANONYMOUS;
        routing.groupPubKey = cursor.readField();
    } else {
        // Types 1 and 2 included: a message envelope has no body to stream, and routing it here would leave
        // the caller with a handle onto data that does not exist.
        throw InvalidEnvelopeFormatException("not a file envelope");
    }
    return routing;
}
