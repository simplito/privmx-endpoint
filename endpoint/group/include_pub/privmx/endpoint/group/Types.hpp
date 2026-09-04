#ifndef _PRIVMXLIB_ENDPOINT_GROUP_TYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_TYPES_HPP_

#include <optional>
#include <string>
#include <vector>

#include "privmx/endpoint/core/Buffer.hpp"
#include "privmx/endpoint/core/Types.hpp"

namespace privmx {
namespace endpoint {
namespace group {

/**
 * Names for the primitives this API passes around.
 *
 * These are aliases, not distinct types. `FileHandle` and `FileSize` are both `int64_t`, and nothing stops
 * you passing one where the other belongs — the compiler cannot help here, and pretending otherwise would be
 * worse than saying so. What they buy is a signature that states its own meaning, carried through to the
 * generated documentation and to the language bindings. Enforcement lives in argument validation and in the
 * tests, not in the type system.
 */

/** ID of a Group. */
using GroupId = std::string;
/** ID of one of a Group's symmetric data keys. */
using KeyId = std::string;
/** A public key, base58-DER encoded. */
using PubKey = std::string;
/** A sealed envelope, as produced by `encrypt` / `encryptAnonymously` / `finishFileEncryption`. */
using Envelope = core::Buffer;
/** An open encrypted-file handle. Opaque — its numeric value carries no meaning. */
using FileHandle = int64_t;
/** A length in bytes of file plaintext. */
using FileSize = int64_t;
/** A position in bytes within a file's plaintext. */
using FilePosition = int64_t;
/** A position in bytes within a file's *ciphertext* — what `seekInEncryptedFile` hands back. */
using CipherOffset = int64_t;

/**
 * Holds all available information about a Group.
 */
/**
 * One member to seat, and the role they take.
 *
 * The role travels per member rather than per call: seating a manager and a user together is one delta over the
 * union of their paths, and splitting it into two calls would be two of everything for no reason.
 */
struct GroupMemberToAdd {
    core::UserWithPubKey user;
    /** "user" or "manager". */
    std::string role;
};

struct Group {
    /**
     * ID of the Context
     */
    std::string contextId;

    /**
     * ID of the Group
     */
    std::string groupId;

    /**
     * Group identity public key (base58-DER encoded)
     */
    std::string groupPubKey;

    /**
     * Group creation timestamp
     */
    int64_t createDate;

    /**
     * ID of user who created the Group
     */
    std::string creator;

    /**
     * Group last modification timestamp
     */
    int64_t lastModificationDate;

    /**
     * ID of the user who last modified the Group
     */
    std::string lastModifier;

    /**
     * list of users (their IDs) with access to the Group
     */
    std::vector<std::string> users;

    /**
     * list of users (their IDs) with management rights
     */
    std::vector<std::string> managers;

    /**
     * version number (= number of history entries; changes on updates)
     */
    int64_t version;

    /**
     * Group's public metadata
     */
    core::Buffer publicMeta;

    /**
     * Group's private metadata
     */
    core::Buffer privateMeta;

    /**
     * Group's policies
     */
    core::ContainerPolicy policy;

    /**
     * status code of retrieval and verification of the Group (0 = success)
     */
    int64_t statusCode;

    /**
     * Version of the Group data structure and how it is encoded/encrypted
     */
    int64_t schemaVersion;

    /**
     * Optional type tag
     */
    std::optional<std::string> type;

    /**
     * Epoch counter for the group identity keypair. Increments by 1 on each key rotation
     * triggered by a member removal. Matches the bridge's CAS field. 0 for Phase-1 groups
     * whose bridge does not yet emit this field.
     */
    int64_t keyVersion;
};

/**
 * Holds the information about a Group that a listing serves: identity, roster, epoch and policies.
 *
 * A listing deliberately carries no per-Group state — the Bridge does not send the encrypted data, the
 * key entries or the history for a page of Groups, because those grow with membership and with every
 * change. So there is no `publicMeta`/`privateMeta` here (nothing to decrypt from), no `schemaVersion`
 * (it is recorded inside the encrypted data), and no `statusCode` (nothing was decrypted or verified,
 * so there is no status to report). Call `getGroup` for any of those.
 */
struct GroupSummary {
    /**
     * ID of the Context
     */
    std::string contextId;

    /**
     * ID of the Group
     */
    std::string groupId;

    /**
     * Group identity public key (base58-DER encoded)
     */
    std::string groupPubKey;

    /**
     * Group creation timestamp
     */
    int64_t createDate;

    /**
     * ID of user who created the Group
     */
    std::string creator;

    /**
     * Group last modification timestamp
     */
    int64_t lastModificationDate;

    /**
     * ID of the user who last modified the Group
     */
    std::string lastModifier;

    /**
     * list of users (their IDs) with access to the Group
     */
    std::vector<std::string> users;

    /**
     * list of users (their IDs) with management rights
     */
    std::vector<std::string> managers;

    /**
     * version number (= number of history entries; changes on updates)
     */
    int64_t version;

    /**
     * Group's policies
     */
    core::ContainerPolicy policy;

    /**
     * Optional type tag
     */
    std::optional<std::string> type;

    /**
     * Epoch counter for the group identity keypair. Increments by 1 on each key rotation
     * triggered by a member removal. Matches the bridge's CAS field. 0 for Phase-1 groups
     * whose bridge does not yet emit this field.
     */
    int64_t keyVersion;
};

/**
 * Which key an envelope was sealed with, and therefore what its author field is worth.
 */
enum EnvelopeType : int64_t {
    /** Sealed with the Group's symmetric data key by a member, and signed by them. */
    ENVELOPE_FROM_MEMBER = 1,
    /** Sealed to the Group's identity public key by an outsider using a throwaway keypair. Unattributable. */
    ENVELOPE_ANONYMOUS = 2,
};

/**
 * The plaintext of an envelope, together with what could be established about who wrote it.
 */
struct DecryptedEnvelope {
    /**
     * Decrypted content
     */
    core::Buffer data;

    /**
     * ID of the Group the envelope was sealed for. Authenticated — an envelope that names a Group it was not
     * sealed for does not decrypt.
     */
    std::string groupId;

    /**
     * Public key of the author (base58-DER encoded), whose signature over the envelope has been verified.
     *
     * EMPTY when `type` is ENVELOPE_ANONYMOUS: that envelope was sealed with a throwaway keypair, which
     * attests to nothing. Branch on `type`, not on this field being non-empty.
     */
    std::string authorPubKey;

    /**
     * Which of the Group's keys sealed this envelope.
     */
    EnvelopeType type;
};

/**
 * What could be established about a sealed file, once all of it has been received.
 *
 * Reported at the end rather than the start deliberately: attributing a file before its last chunk has
 * arrived would attribute something the sender may not have finished writing.
 */
struct DecryptedFileInfo {
    /**
     * ID of the Group the file was sealed for
     */
    std::string groupId;

    /**
     * Public key of the author (base58-DER encoded), whose signature over the file header has been verified.
     *
     * EMPTY when `type` is ENVELOPE_ANONYMOUS. Branch on `type`, not on this field being non-empty.
     */
    std::string authorPubKey;

    /**
     * Whether the file came from a member or from an anonymous outsider.
     */
    EnvelopeType type;

    /**
     * Whether the whole file was verified to be present.
     *
     * True for a straight read from start to finish: every chunk the envelope's signed size called for
     * arrived. False once `seekInEncryptedFile` has been used — the parts you did read are still individually
     * authenticated and cannot have been reordered or substituted, but nothing can tell you whether the parts
     * you skipped exist at all. That is inherent to random access, not a weakness of the seek.
     */
    bool complete;
};

enum EventType : int64_t {
    GROUP_CREATE = 0,
    GROUP_UPDATE = 1,
    GROUP_DELETE = 2,
};

enum EventSelectorType : int64_t {
    CONTEXT_ID = 0,
    GROUP_ID = 1,
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_TYPES_HPP_
