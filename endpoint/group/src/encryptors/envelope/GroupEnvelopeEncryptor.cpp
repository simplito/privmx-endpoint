#include "privmx/endpoint/group/encryptors/envelope/GroupEnvelopeEncryptor.hpp"

#include <privmx/crypto/Crypto.hpp>
#include <privmx/endpoint/core/crypto/Ecies.hpp>
#include <privmx/endpoint/core/crypto/PublicKeyCache.hpp>
#include <privmx/endpoint/core/CoreException.hpp>

#include "privmx/endpoint/group/GroupException.hpp"
#include "privmx/endpoint/group/encryptors/envelope/EnvelopeWire.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::group;

namespace {

/**
 * Opakowuje goly klucz w `core::EncKey` z zestawem domyslnym dla buildu.
 *
 * Koperty grupowe celowo **nie** podlegaja wyborowi zestawu z polityki kontenera, z dwoch powodow:
 *  - to warstwa zewnetrzna (dostep do kontenera: owijanie kluczy grupy do kluczy tozsamosci),
 *    a ta jest ustalona z zalozenia - na jednego uzytkownika przypada jeden klucz;
 *  - `encryptedChunkSizeFor` liczy rozmiar zaszyfrowanego chunku ze stalej `DEFAULT_FRAME_OVERHEAD`,
 *    a chunki sa adresowane jako `index * ENCRYPTED_CHUNK_SIZE`. Zestaw o innym narzucie ramki
 *    rozjechalby to adresowanie - dokladnie ten sam problem co w `store` (crypto-update/zmiany-endpoint.md §5.2).
 *
 * Nie zamieniac tego na zestaw z polityki bez zmiany sposobu adresowania chunkow.
 */
core::EncKey fixedSuiteKey(const std::string& key) {
    return core::EncKey{.id = "", .key = key};
}

} // namespace

// Load-bearing: epoch-ladder rungs wrap a past grant private key to the same key with the same `EciesEncryptor`,
// so without this prefix a rung could be replayed as a type 2 envelope and opened as message content.
const std::string GroupEnvelopeEncryptor::ECIES_DOMAIN = "PMXENV1";

// Domain label on the per-chunk key derivation. See `chunkKey`.
const std::string GroupEnvelopeEncryptor::CHUNK_KEY_LABEL = "privmx/group/file-chunk";

std::string GroupEnvelopeEncryptor::writeHeader(std::uint8_t type, const std::vector<std::string>& fields) {
    std::string header;
    header.push_back(static_cast<char>(VERSION));
    header.push_back(static_cast<char>(type));
    for (const std::string& field : fields) {
        EnvelopeWriter::putField(header, field);
    }
    return header;
}

std::pair<ByteCount, std::string> GroupEnvelopeEncryptor::readFileBody(
    const std::string& plain,
    const std::string& header
) {
    EnvelopeReader inner(plain);
    inner.skip(header.size());
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

std::pair<std::string, std::string> GroupEnvelopeEncryptor::wrapContentKey(
    const core::PublicKey& groupPubKey
) {
    // Throwaway, never retained: it exists only to carry out one ECDH with the group's identity key.
    core::PrivateKey ephemeralPrivKey = core::PrivateKey::generateRandom();
    std::string contentKey = core::CryptoSuite::randomBytes(CONTENT_KEY_SIZE);
    std::string wrap = core::Ecies::encrypt(
        groupPubKey, ECIES_DOMAIN + contentKey, ephemeralPrivKey
    );
    return {wrap, contentKey};
}

std::string GroupEnvelopeEncryptor::unwrapContentKey(
    const core::PrivateKey& groupPrivKey,
    const std::string& groupPubKeyBase58,
    const std::string& wrap
) {
    // The key we resolved must be the key the envelope names, or a hostile server could steer us onto another
    // epoch's key with only the ECIES 4-byte checksum between us and a wrong answer.
    if (groupPrivKey.getPublicKey() !=
        core::PublicKeyCache::getInstance()->fromBase58DER(groupPubKeyBase58)) {
        throw InvalidEnvelopeFormatException("resolved group key does not match the key named by the envelope");
    }
    std::string unwrapped = core::Ecies::decrypt(groupPrivKey, wrap);
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
    const core::PrivateKey& authorPrivKey,
    const std::string& groupKey
) {
    std::string header = writeHeader(TYPE_GROUP_KEY, {groupId, keyId, authorPrivKey.getPublicKey().toDER()});
    core::Buffer signed_ = _dataEncryptor.signAndPackDataWithSignature(
        core::Buffer::from(header + content.stdString()), authorPrivKey
    );
    return core::Buffer::from(header + _dataEncryptor.encrypt(signed_, fixedSuiteKey(groupKey)).stdString());
}

DecryptedEnvelope GroupEnvelopeEncryptor::openGroupKeyEnvelope(
    const core::Buffer& envelope,
    const std::string& groupKey
) {
    EnvelopeReader cursor(envelope.stdString());
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

    core::PublicKey authorPubKey = core::PublicKey::fromDER(authorPubKeyDer);
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
    const core::PublicKey& groupPubKey,
    const core::Buffer& content
) {
    auto [wrap, contentKey] = wrapContentKey(groupPubKey);
    std::string header = writeHeader(TYPE_ANONYMOUS, {groupId, groupPubKey.toBase58DER()});

    std::string out = header;
    EnvelopeWriter::putField(out, wrap);
    // No author signature: the sender is anonymous by construction, so a signature by the throwaway key would
    // attest to nothing. The header is authenticated by being inside this encrypt-then-MAC payload.
    out.append(
        _dataEncryptor.encrypt(core::Buffer::from(header + content.stdString()), fixedSuiteKey(contentKey)).stdString()
    );
    return core::Buffer::from(out);
}

DecryptedEnvelope GroupEnvelopeEncryptor::openAnonymousEnvelope(
    const core::Buffer& envelope,
    const core::PrivateKey& groupPrivKey
) {
    EnvelopeReader cursor(envelope.stdString());
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
    const core::PrivateKey& authorPrivKey,
    const std::string& groupKey
) {
    std::string header = writeHeader(TYPE_FILE, {groupId, keyId, authorPrivKey.getPublicKey().toDER()});
    // `plainSize` inside the signature is the only thing that makes a dropped trailing chunk detectable —
    // each chunk authenticates itself, but nothing about chunk N says how many were supposed to follow.
    std::string body = header + EnvelopeWriter::toBE(plainSize, 8) + fileKey;
    core::Buffer signed_ = _dataEncryptor.signAndPackDataWithSignature(core::Buffer::from(body), authorPrivKey);
    return core::Buffer::from(header + _dataEncryptor.encrypt(signed_, fixedSuiteKey(groupKey)).stdString());
}

EnvelopeFileHeader GroupEnvelopeEncryptor::unpackFileEnvelope(
    const core::Buffer& envelope,
    const std::string& groupKey
) {
    EnvelopeReader cursor(envelope.stdString());
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

    core::PublicKey authorPubKey = core::PublicKey::fromDER(authorPubKeyDer);
    core::Buffer plain = _dataEncryptor.verifyAndExtractData(
        _dataEncryptor.decrypt(core::Buffer::from(cursor.readRest()), groupKey), authorPubKey
    );
    if (plain.stdString().rfind(header, 0) != 0) {
        throw InvalidEnvelopeFormatException("envelope header does not match the signed header");
    }

    auto [plainSize, fileKey] = readFileBody(plain.stdString(), header);
    return EnvelopeFileHeader{
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
    const core::PublicKey& groupPubKey,
    ByteCount plainSize,
    const std::string& fileKey
) {
    auto [wrap, contentKey] = wrapContentKey(groupPubKey);
    std::string header = writeHeader(TYPE_ANON_FILE, {groupId, groupPubKey.toBase58DER()});

    std::string out = header;
    EnvelopeWriter::putField(out, wrap);
    // No signature, for the same reason as type 2: the sender is anonymous by construction. `plainSize` still
    // sits inside this encrypt-then-MAC payload, so a dropped tail stays detectable.
    out.append(_dataEncryptor
                   .encrypt(
                       core::Buffer::from(header + EnvelopeWriter::toBE(plainSize, 8) + fileKey),
                       fixedSuiteKey(contentKey)
                   )
                   .stdString());
    return core::Buffer::from(out);
}

EnvelopeFileHeader GroupEnvelopeEncryptor::unpackAnonymousFileEnvelope(
    const core::Buffer& envelope,
    const core::PrivateKey& groupPrivKey
) {
    EnvelopeReader cursor(envelope.stdString());
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

    auto [plainSize, fileKey] = readFileBody(plain.stdString(), header);
    return EnvelopeFileHeader{
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
    return _dataEncryptor.encrypt(plainChunk, fixedSuiteKey(chunkKey(fileKey, index)));
}

core::Buffer GroupEnvelopeEncryptor::decryptChunk(
    const core::Buffer& cipherChunk,
    const std::string& fileKey,
    ChunkIndex index
) {
    return _dataEncryptor.decrypt(cipherChunk, chunkKey(fileKey, index));
}

// -- dispatch ------------------------------------------------------------------------------------------

EnvelopeRouting GroupEnvelopeEncryptor::peekFamily(const core::Buffer& envelope, EnvelopeFamily family) {
    // The member and anonymous headers are shaped alike in both families, so only the acceptable type bytes
    // vary. Crossing the families is refused — see the notes on `peek` and `peekFile`.
    const bool wantFile = family == EnvelopeFamily::File;
    const std::uint8_t memberType = wantFile ? TYPE_FILE : TYPE_GROUP_KEY;
    const std::uint8_t anonType = wantFile ? TYPE_ANON_FILE : TYPE_ANONYMOUS;

    EnvelopeReader cursor(envelope.stdString());
    if (cursor.readU8() != VERSION) {
        throw InvalidEnvelopeFormatException("unsupported envelope version");
    }
    std::uint8_t type = cursor.readU8();
    EnvelopeRouting routing;
    routing.groupId = cursor.readField();
    if (type == memberType) {
        routing.type = ENVELOPE_FROM_MEMBER;
        routing.keyId = cursor.readField();
    } else if (type == anonType) {
        routing.type = ENVELOPE_ANONYMOUS;
        routing.groupPubKey = cursor.readField();
    } else {
        throw InvalidEnvelopeFormatException(wantFile ? "not a file envelope" : "unsupported envelope type");
    }
    return routing;
}
