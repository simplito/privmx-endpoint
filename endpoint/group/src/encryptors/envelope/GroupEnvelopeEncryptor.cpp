#include "privmx/endpoint/group/encryptors/envelope/GroupEnvelopeEncryptor.hpp"

#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/EciesEncryptor.hpp>
#include <privmx/crypto/ecc/PublicKeyCache.hpp>
#include <privmx/endpoint/core/CoreException.hpp>

#include "privmx/endpoint/group/GroupException.hpp"
#include "privmx/endpoint/group/encryptors/envelope/EnvelopeWire.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::group;

// Load-bearing: epoch-ladder rungs wrap a past grant private key to the same key with the same `EciesEncryptor`,
// so without this prefix a rung could be replayed as a type 2 envelope and opened as message content.
const std::string GroupEnvelopeEncryptor::ECIES_DOMAIN = "PMXENV1";

// Domain label on the per-chunk key derivation. See `chunkKey`.
const std::string GroupEnvelopeEncryptor::CHUNK_KEY_LABEL = "privmx/group/file-chunk";

// Domain label on the location digest: a digest of a path can never be mistaken for a digest of anything else.
const std::string GroupEnvelopeEncryptor::LOCATION_LABEL = "privmx/group/location";

// Domain label on a content key sealed under a group's symmetric key (type 6). Without it that seal is an
// ordinary ciphertext under the group key, which is also what a type 1 payload is.
const std::string GroupEnvelopeEncryptor::KEY_WRAP_LABEL = "PMXENVK";

// -- header --------------------------------------------------------------------------------------------

EnvelopeBinding GroupEnvelopeEncryptor::bindLocation(const Path& location) {
    if (location.empty()) {
        // With no segment every value of a group would be bound to the same spot, and any two could be swapped.
        throw InvalidEnvelopeFormatException("a location needs at least one segment");
    }
    // Length-prefixed and kind-tagged, so no two different paths share an encoding: {"ab"} is not {"a","b"},
    // and a name is not an identifier with the same bytes.
    std::string canonical = EnvelopeWriter::toBE(location.size(), 4);
    for (const PathSegment& segment : location) {
        canonical.push_back(segment.isId ? '\x01' : '\x00');
        canonical.append(EnvelopeWriter::toBE(segment.value.size(), 4));
        canonical.append(segment.value.stdString());
    }
    return EnvelopeBinding{
        .hasLocation = true, .locationDigest = privmx::crypto::Crypto::sha256(LOCATION_LABEL + canonical)
    };
}

std::string GroupEnvelopeEncryptor::writeHeader(
    std::uint8_t type,
    const EnvelopeBinding& binding,
    const std::vector<std::string>& fields
) {
    if (binding.hasLocation != (binding.locationDigest.size() == LOCATION_DIGEST_SIZE) ||
        (!binding.hasLocation && !binding.locationDigest.empty())) {
        throw InvalidEnvelopeFormatException("malformed location binding");
    }
    std::string header;
    header.push_back(static_cast<char>(VERSION));
    header.push_back(static_cast<char>(type));
    header.push_back(static_cast<char>(binding.hasLocation ? FLAG_HAS_LOCATION : 0));
    for (const std::string& field : fields) {
        EnvelopeWriter::putField(header, field);
    }
    return header;
}

void GroupEnvelopeEncryptor::putRecipients(std::string& header, const std::vector<EnvelopeRecipient>& recipients) {
    if (recipients.size() > 255) {
        throw InvalidEnvelopeFormatException("an envelope takes at most 255 further recipients");
    }
    header.push_back(static_cast<char>(recipients.size()));
    for (const EnvelopeRecipient& recipient : recipients) {
        header.push_back(static_cast<char>(recipient.isGroup ? RECIPIENT_GROUP : RECIPIENT_USER));
        EnvelopeWriter::putField(header, recipient.id);
        EnvelopeWriter::putField(header, recipient.pubKey);
        header.append(EnvelopeWriter::toBE(static_cast<std::uint64_t>(recipient.keyVersion), 8));
    }
}

GroupEnvelopeEncryptor::ParsedHeader GroupEnvelopeEncryptor::parseHeader(EnvelopeReader& cursor) {
    if (cursor.readU8() != VERSION) {
        throw InvalidEnvelopeFormatException("unsupported envelope version");
    }
    ParsedHeader header;
    header.wireType = cursor.readU8();
    std::uint8_t flags = cursor.readU8();
    if ((flags & ~FLAG_HAS_LOCATION) != 0) {
        throw InvalidEnvelopeFormatException("unknown envelope flags");
    }
    EnvelopeRouting& routing = header.routing;
    routing.hasLocation = (flags & FLAG_HAS_LOCATION) != 0;
    routing.groupId = cursor.readField();

    const std::uint8_t type = header.wireType;
    const bool memberKeyed = type == TYPE_GROUP_KEY || type == TYPE_MEMBER_SHARED || type == TYPE_FILE;
    const bool pubKeyed = type == TYPE_ANONYMOUS || type == TYPE_ANON_FILE || type == TYPE_OUTSIDER;
    if (!memberKeyed && !pubKeyed) {
        throw InvalidEnvelopeFormatException("unsupported envelope type");
    }
    routing.isFile = type == TYPE_FILE || type == TYPE_ANON_FILE;
    if (memberKeyed) {
        routing.type = ENVELOPE_FROM_MEMBER;
        routing.keyId = cursor.readField();
        routing.authorUserId = cursor.readField();
        routing.authorPubKey = privmx::crypto::PublicKey::fromDER(cursor.readField()).toBase58DER();
        routing.keyVersion = static_cast<std::int64_t>(cursor.readU64());
    } else {
        routing.type = type == TYPE_OUTSIDER ? ENVELOPE_FROM_OUTSIDER : ENVELOPE_ANONYMOUS;
        routing.groupPubKey = cursor.readField();
        if (type == TYPE_OUTSIDER) {
            routing.authorUserId = cursor.readField();
            routing.authorPubKey = privmx::crypto::PublicKey::fromDER(cursor.readField()).toBase58DER();
        }
    }
    if (type == TYPE_OUTSIDER || type == TYPE_MEMBER_SHARED) {
        std::size_t count = cursor.readU8();
        routing.recipients.reserve(count);
        for (std::size_t i = 0; i < count; ++i) {
            EnvelopeRecipient recipient;
            std::uint8_t kind = cursor.readU8();
            if (kind != RECIPIENT_GROUP && kind != RECIPIENT_USER) {
                throw InvalidEnvelopeFormatException("unknown envelope recipient kind");
            }
            recipient.isGroup = kind == RECIPIENT_GROUP;
            recipient.id = cursor.readField();
            recipient.pubKey = cursor.readField();
            recipient.keyVersion = static_cast<std::int64_t>(cursor.readU64());
            routing.recipients.push_back(std::move(recipient));
        }
    }
    header.bytes = cursor.consumed();
    return header;
}

std::size_t GroupEnvelopeEncryptor::checkSealedPrefix(
    const std::string& plain,
    const ParsedHeader& header,
    const EnvelopeBinding& binding
) {
    // The header the writer signed (or sealed) must be the header we were served. Anything else is a rewrite:
    // another group's id, another key, another author, another list of readers, or a relabelled type.
    if (plain.rfind(header.bytes, 0) != 0) {
        throw InvalidEnvelopeFormatException("envelope header does not match the sealed header");
    }
    std::size_t offset = header.bytes.size();
    // From here on the envelope is authentic; what is left to decide is whether it belongs where it was found.
    if (header.routing.hasLocation != binding.hasLocation) {
        throw EnvelopeWrongLocationException(
            binding.hasLocation ? "envelope is bound to no location" : "envelope is bound to a location"
        );
    }
    if (binding.hasLocation) {
        if (plain.size() - offset < LOCATION_DIGEST_SIZE) {
            throw InvalidEnvelopeFormatException("envelope truncated");
        }
        if (plain.compare(offset, LOCATION_DIGEST_SIZE, binding.locationDigest) != 0) {
            throw EnvelopeWrongLocationException("envelope was written for another location");
        }
        offset += LOCATION_DIGEST_SIZE;
    }
    return offset;
}

std::pair<ByteCount, std::string> GroupEnvelopeEncryptor::readFileBody(const std::string& plain, std::size_t offset) {
    EnvelopeReader inner(plain);
    inner.skip(offset);
    ByteCount plainSize = inner.readU64();
    std::string fileKey = inner.readRest();
    if (fileKey.size() != CONTENT_KEY_SIZE) {
        throw InvalidEnvelopeFormatException("file envelope carries a malformed file key");
    }
    return {plainSize, fileKey};
}

std::string GroupEnvelopeEncryptor::chunkKey(const std::string& fileKey, ChunkIndex index) {
    // Binding the index makes a chunk unusable in any other position; binding the per-file key makes it
    // unusable in any other file. The label keeps this separate from future derivations off the same key.
    return privmx::crypto::Crypto::hmacSha256(fileKey, CHUNK_KEY_LABEL + EnvelopeWriter::toBE(index, 4));
}

std::string GroupEnvelopeEncryptor::wrapContentKey(
    const privmx::crypto::PublicKey& pubKey,
    const std::string& contentKey
) {
    // Throwaway, never retained: it exists only to carry out one ECDH with the reader's key. A fresh one per
    // wrap, because the ECIES layer derives its IV from the sender key.
    privmx::crypto::PrivateKey ephemeralPrivKey = privmx::crypto::PrivateKey::generateRandom();
    return privmx::crypto::EciesEncryptor::encrypt(pubKey, ECIES_DOMAIN + contentKey, ephemeralPrivKey);
}

std::string GroupEnvelopeEncryptor::unwrapContentKey(
    const privmx::crypto::PrivateKey& groupPrivKey,
    const std::string& groupPubKeyBase58,
    const std::string& wrap
) {
    // The key we resolved must be the key the envelope names, or a hostile server could steer us onto another
    // epoch's key with only the ECIES 4-byte checksum between us and a wrong answer.
    if (groupPrivKey.getPublicKey() !=
        privmx::crypto::PublicKeyCache::getInstance()->fromBase58DER(groupPubKeyBase58)) {
        throw InvalidEnvelopeFormatException("resolved key does not match the key named by the envelope");
    }
    std::string unwrapped = privmx::crypto::EciesEncryptor::decrypt(groupPrivKey, wrap);
    if (unwrapped.rfind(ECIES_DOMAIN, 0) != 0 || unwrapped.size() != ECIES_DOMAIN.size() + CONTENT_KEY_SIZE) {
        // Not one of ours. Most importantly: an epoch-ladder rung, which is the same ECIES construction
        // addressed to the same key but carries a grant private key. See ECIES_DOMAIN above.
        throw InvalidEnvelopeFormatException("wrapped key is not a group envelope key");
    }
    return unwrapped.substr(ECIES_DOMAIN.size());
}

// -- signed messages: types 1, 5, 6 ----------------------------------------------------------------------

core::Buffer GroupEnvelopeEncryptor::signMessage(
    const std::string& header,
    const EnvelopeSeal& seal,
    const core::Buffer& content,
    const privmx::crypto::PrivateKey& signer
) {
    return _dataEncryptor.signAndPackDataWithSignature(
        core::Buffer::from(
            header +
            seal.binding.locationDigest +
            EnvelopeWriter::toBE(static_cast<std::uint64_t>(seal.encryptedAt), 8) +
            content.stdString()
        ),
        signer
    );
}

OpenedEnvelope GroupEnvelopeEncryptor::openSignedMessage(
    const std::string& sealed,
    const std::string& contentKey,
    const ParsedHeader& header,
    const EnvelopeBinding& binding,
    EnvelopeType type
) {
    privmx::crypto::PublicKey authorPubKey = privmx::crypto::PublicKey::fromBase58DER(header.routing.authorPubKey);
    std::string plain = _dataEncryptor
                            .verifyAndExtractData(
                                _dataEncryptor.decrypt(core::Buffer::from(sealed), contentKey), authorPubKey
                            )
                            .stdString();
    std::size_t offset = checkSealedPrefix(plain, header, binding);
    EnvelopeReader inner(plain);
    inner.skip(offset);
    std::int64_t encryptedAt = static_cast<std::int64_t>(inner.readU64());
    return OpenedEnvelope{
        .data = core::Buffer::from(inner.readRest()),
        .groupId = header.routing.groupId,
        .keyId = header.routing.keyId,
        .keyVersion = header.routing.keyVersion,
        .authorUserId = header.routing.authorUserId,
        .authorPubKey = header.routing.authorPubKey,
        .encryptedAt = encryptedAt,
        .recipients = header.routing.recipients,
        .type = type,
    };
}

core::Buffer GroupEnvelopeEncryptor::packMemberEnvelope(
    const std::string& groupId,
    const std::string& keyId,
    const core::Buffer& content,
    const privmx::crypto::PrivateKey& authorPrivKey,
    const std::string& groupKey,
    const EnvelopeSeal& seal,
    const std::vector<EnvelopeRecipient>& recipients
) {
    const bool shared = !recipients.empty();
    std::string header = writeHeader(
        shared ? TYPE_MEMBER_SHARED : TYPE_GROUP_KEY, seal.binding,
        {groupId, keyId, seal.authorUserId, authorPrivKey.getPublicKey().toDER()}
    );
    header.append(EnvelopeWriter::toBE(static_cast<std::uint64_t>(seal.keyVersion), 8));
    if (!shared) {
        return core::Buffer::from(
            header + _dataEncryptor.encrypt(signMessage(header, seal, content, authorPrivKey), groupKey).stdString()
        );
    }
    putRecipients(header, recipients);
    std::string contentKey = privmx::crypto::Crypto::randomBytes(CONTENT_KEY_SIZE);
    std::string out = header;
    EnvelopeWriter::putField(
        out, _dataEncryptor.encrypt(core::Buffer::from(KEY_WRAP_LABEL + contentKey), groupKey).stdString()
    );
    for (const EnvelopeRecipient& recipient : recipients) {
        EnvelopeWriter::putField(
            out, wrapContentKey(privmx::crypto::PublicKey::fromBase58DER(recipient.pubKey), contentKey)
        );
    }
    out.append(_dataEncryptor.encrypt(signMessage(header, seal, content, authorPrivKey), contentKey).stdString());
    return core::Buffer::from(out);
}

OpenedEnvelope GroupEnvelopeEncryptor::openMemberEnvelope(
    const core::Buffer& envelope,
    const std::string& groupKey,
    const EnvelopeBinding& binding
) {
    EnvelopeReader cursor(envelope.stdString());
    ParsedHeader header = parseHeader(cursor);
    if (header.wireType == TYPE_GROUP_KEY) {
        return openSignedMessage(cursor.readRest(), groupKey, header, binding, ENVELOPE_FROM_MEMBER);
    }
    if (header.wireType != TYPE_MEMBER_SHARED) {
        throw InvalidEnvelopeFormatException("not a member envelope");
    }
    std::string wrapped = _dataEncryptor.decrypt(core::Buffer::from(cursor.readField()), groupKey).stdString();
    if (wrapped.rfind(KEY_WRAP_LABEL, 0) != 0 || wrapped.size() != KEY_WRAP_LABEL.size() + CONTENT_KEY_SIZE) {
        throw InvalidEnvelopeFormatException("wrapped key is not a group envelope key");
    }
    for (std::size_t i = 0; i < header.routing.recipients.size(); ++i) {
        cursor.readField(); // the other readers' wraps
    }
    return openSignedMessage(
        cursor.readRest(), wrapped.substr(KEY_WRAP_LABEL.size()), header, binding, ENVELOPE_FROM_MEMBER
    );
}

core::Buffer GroupEnvelopeEncryptor::packOutsiderEnvelope(
    const std::string& groupId,
    const privmx::crypto::PublicKey& groupPubKey,
    const core::Buffer& content,
    const privmx::crypto::PrivateKey& senderPrivKey,
    const EnvelopeSeal& seal,
    const std::vector<EnvelopeRecipient>& recipients
) {
    std::string header = writeHeader(
        TYPE_OUTSIDER, seal.binding,
        {groupId, groupPubKey.toBase58DER(), seal.authorUserId, senderPrivKey.getPublicKey().toDER()}
    );
    putRecipients(header, recipients);
    std::string contentKey = privmx::crypto::Crypto::randomBytes(CONTENT_KEY_SIZE);
    std::string out = header;
    EnvelopeWriter::putField(out, wrapContentKey(groupPubKey, contentKey));
    for (const EnvelopeRecipient& recipient : recipients) {
        EnvelopeWriter::putField(
            out, wrapContentKey(privmx::crypto::PublicKey::fromBase58DER(recipient.pubKey), contentKey)
        );
    }
    out.append(_dataEncryptor.encrypt(signMessage(header, seal, content, senderPrivKey), contentKey).stdString());
    return core::Buffer::from(out);
}

OpenedEnvelope GroupEnvelopeEncryptor::openOutsiderEnvelope(
    const core::Buffer& envelope,
    const privmx::crypto::PrivateKey& groupPrivKey,
    const EnvelopeBinding& binding
) {
    EnvelopeReader cursor(envelope.stdString());
    ParsedHeader header = parseHeader(cursor);
    if (header.wireType != TYPE_OUTSIDER) {
        throw InvalidEnvelopeFormatException("not an outsider envelope");
    }
    std::string contentKey = unwrapContentKey(groupPrivKey, header.routing.groupPubKey, cursor.readField());
    for (std::size_t i = 0; i < header.routing.recipients.size(); ++i) {
        cursor.readField();
    }
    return openSignedMessage(cursor.readRest(), contentKey, header, binding, ENVELOPE_FROM_OUTSIDER);
}

OpenedEnvelope GroupEnvelopeEncryptor::openSharedEnvelope(
    const core::Buffer& envelope,
    std::size_t recipientIndex,
    const privmx::crypto::PrivateKey& recipientPrivKey,
    const EnvelopeBinding& binding
) {
    EnvelopeReader cursor(envelope.stdString());
    ParsedHeader header = parseHeader(cursor);
    if (header.wireType != TYPE_OUTSIDER && header.wireType != TYPE_MEMBER_SHARED) {
        throw InvalidEnvelopeFormatException("not a shared envelope");
    }
    if (recipientIndex >= header.routing.recipients.size()) {
        throw EnvelopeNotARecipientException();
    }
    cursor.readField(); // the home group's wrap
    std::string wrap;
    for (std::size_t i = 0; i < header.routing.recipients.size(); ++i) {
        std::string field = cursor.readField();
        if (i == recipientIndex) {
            wrap = std::move(field);
        }
    }
    std::string contentKey = unwrapContentKey(recipientPrivKey, header.routing.recipients[recipientIndex].pubKey, wrap);
    OpenedEnvelope opened = openSignedMessage(
        cursor.readRest(), contentKey, header, binding,
        header.wireType == TYPE_OUTSIDER ? ENVELOPE_FROM_OUTSIDER : ENVELOPE_FROM_MEMBER
    );
    // A recipient holds only its own wrap, never the home group's key: nothing here shows that the writer could
    // open the home wrap, or that there is a group behind `groupId` at all. `type` is the writer's claim.
    opened.homeGroupUnverified = true;
    return opened;
}

// -- type 2 --------------------------------------------------------------------------------------------

core::Buffer GroupEnvelopeEncryptor::packAnonymousEnvelope(
    const std::string& groupId,
    const privmx::crypto::PublicKey& groupPubKey,
    const core::Buffer& content,
    const EnvelopeBinding& binding
) {
    std::string contentKey = privmx::crypto::Crypto::randomBytes(CONTENT_KEY_SIZE);
    std::string header = writeHeader(TYPE_ANONYMOUS, binding, {groupId, groupPubKey.toBase58DER()});

    std::string out = header;
    EnvelopeWriter::putField(out, wrapContentKey(groupPubKey, contentKey));
    // No author signature: the sender is anonymous by construction, so a signature by the throwaway key would
    // attest to nothing. The header is authenticated by being inside this encrypt-then-MAC payload.
    out.append(_dataEncryptor
                   .encrypt(core::Buffer::from(header + binding.locationDigest + content.stdString()), contentKey)
                   .stdString());
    return core::Buffer::from(out);
}

OpenedEnvelope GroupEnvelopeEncryptor::openAnonymousEnvelope(
    const core::Buffer& envelope,
    const privmx::crypto::PrivateKey& groupPrivKey,
    const EnvelopeBinding& binding
) {
    EnvelopeReader cursor(envelope.stdString());
    ParsedHeader header = parseHeader(cursor);
    if (header.wireType != TYPE_ANONYMOUS) {
        throw InvalidEnvelopeFormatException("not an anonymous envelope");
    }
    std::string contentKey = unwrapContentKey(groupPrivKey, header.routing.groupPubKey, cursor.readField());
    std::string plain = _dataEncryptor.decrypt(core::Buffer::from(cursor.readRest()), contentKey).stdString();
    std::size_t offset = checkSealedPrefix(plain, header, binding);
    return OpenedEnvelope{
        .data = core::Buffer::from(plain.substr(offset)),
        .groupId = header.routing.groupId,
        .keyId = std::string(),
        .keyVersion = 0,
        // Deliberately empty: the throwaway sender key attests to nothing, so reporting it would invite
        // callers to treat it as an identity.
        .authorUserId = std::string(),
        .authorPubKey = std::string(),
        .encryptedAt = 0,
        .recipients = {},
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
    const std::string& groupKey,
    const EnvelopeSeal& seal
) {
    std::string header = writeHeader(
        TYPE_FILE, seal.binding, {groupId, keyId, seal.authorUserId, authorPrivKey.getPublicKey().toDER()}
    );
    header.append(EnvelopeWriter::toBE(static_cast<std::uint64_t>(seal.keyVersion), 8));
    // `plainSize` inside the signature is the only thing that makes a dropped trailing chunk detectable -
    // each chunk authenticates itself, but nothing about chunk N says how many were supposed to follow.
    std::string body = header + seal.binding.locationDigest + EnvelopeWriter::toBE(plainSize, 8) + fileKey;
    core::Buffer signed_ = _dataEncryptor.signAndPackDataWithSignature(core::Buffer::from(body), authorPrivKey);
    return core::Buffer::from(header + _dataEncryptor.encrypt(signed_, groupKey).stdString());
}

EnvelopeFileHeader GroupEnvelopeEncryptor::unpackFileEnvelope(
    const core::Buffer& envelope,
    const std::string& groupKey,
    const EnvelopeBinding& binding
) {
    EnvelopeReader cursor(envelope.stdString());
    ParsedHeader header = parseHeader(cursor);
    if (header.wireType != TYPE_FILE) {
        throw InvalidEnvelopeFormatException("not a file envelope");
    }
    privmx::crypto::PublicKey authorPubKey = privmx::crypto::PublicKey::fromBase58DER(header.routing.authorPubKey);
    std::string plain = _dataEncryptor
                            .verifyAndExtractData(
                                _dataEncryptor.decrypt(core::Buffer::from(cursor.readRest()), groupKey), authorPubKey
                            )
                            .stdString();
    auto [plainSize, fileKey] = readFileBody(plain, checkSealedPrefix(plain, header, binding));
    return EnvelopeFileHeader{
        .type = ENVELOPE_FROM_MEMBER,
        .groupId = header.routing.groupId,
        .keyId = header.routing.keyId,
        .keyVersion = header.routing.keyVersion,
        .authorUserId = header.routing.authorUserId,
        .authorPubKey = header.routing.authorPubKey,
        .plainSize = plainSize,
        .fileKey = fileKey,
    };
}

// -- type 4 --------------------------------------------------------------------------------------------

core::Buffer GroupEnvelopeEncryptor::packAnonymousFileEnvelope(
    const std::string& groupId,
    const privmx::crypto::PublicKey& groupPubKey,
    ByteCount plainSize,
    const std::string& fileKey,
    const EnvelopeBinding& binding
) {
    std::string contentKey = privmx::crypto::Crypto::randomBytes(CONTENT_KEY_SIZE);
    std::string header = writeHeader(TYPE_ANON_FILE, binding, {groupId, groupPubKey.toBase58DER()});

    std::string out = header;
    EnvelopeWriter::putField(out, wrapContentKey(groupPubKey, contentKey));
    // No signature, for the same reason as type 2: the sender is anonymous by construction. `plainSize` still
    // sits inside this encrypt-then-MAC payload, so a dropped tail stays detectable.
    out.append(
        _dataEncryptor
            .encrypt(
                core::Buffer::from(header + binding.locationDigest + EnvelopeWriter::toBE(plainSize, 8) + fileKey),
                contentKey
            )
            .stdString()
    );
    return core::Buffer::from(out);
}

EnvelopeFileHeader GroupEnvelopeEncryptor::unpackAnonymousFileEnvelope(
    const core::Buffer& envelope,
    const privmx::crypto::PrivateKey& groupPrivKey,
    const EnvelopeBinding& binding
) {
    EnvelopeReader cursor(envelope.stdString());
    ParsedHeader header = parseHeader(cursor);
    if (header.wireType != TYPE_ANON_FILE) {
        throw InvalidEnvelopeFormatException("not an anonymous file envelope");
    }
    std::string contentKey = unwrapContentKey(groupPrivKey, header.routing.groupPubKey, cursor.readField());
    std::string plain = _dataEncryptor.decrypt(core::Buffer::from(cursor.readRest()), contentKey).stdString();
    auto [plainSize, fileKey] = readFileBody(plain, checkSealedPrefix(plain, header, binding));
    return EnvelopeFileHeader{
        .type = ENVELOPE_ANONYMOUS,
        .groupId = header.routing.groupId,
        .keyId = std::string(),
        .keyVersion = 0,
        // Deliberately empty: the throwaway sender key attests to nothing.
        .authorUserId = std::string(),
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

EnvelopeRouting GroupEnvelopeEncryptor::peekAny(const core::Buffer& envelope) {
    EnvelopeReader cursor(envelope.stdString());
    return parseHeader(cursor).routing;
}

EnvelopeRouting GroupEnvelopeEncryptor::peekFamily(const core::Buffer& envelope, EnvelopeFamily family) {
    // Crossing the families is refused - see the notes on `peek` and `peekFile`.
    EnvelopeRouting routing = peekAny(envelope);
    if (routing.isFile != (family == EnvelopeFamily::File)) {
        throw InvalidEnvelopeFormatException(
            family == EnvelopeFamily::File ? "not a file envelope" : "unsupported envelope type"
        );
    }
    return routing;
}
