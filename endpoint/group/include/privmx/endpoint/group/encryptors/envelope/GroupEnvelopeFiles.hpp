/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_ENVELOPE_GROUPENVELOPEFILES_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_ENVELOPE_GROUPENVELOPEFILES_HPP_

#include <cstdint>
#include <memory>
#include <string>

#include <privmx/endpoint/core/Buffer.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/utils/ThreadSaveMap.hpp>

#include "privmx/endpoint/group/GroupTypes.hpp"
#include "privmx/endpoint/group/Types.hpp"
#include "privmx/endpoint/group/encryptors/envelope/GroupEnvelopeEncryptor.hpp"

namespace privmx {
namespace endpoint {
namespace group {

// The open encrypted-file handles of one GroupApiImpl, each paired with its id in the connection's HandleManager.
// An `EnvelopeFileState` holds the group and file keys as plainly as the sessions' envelope keys do, so the owner
// drops them with those, on connect and disconnect (`clear`).
class GroupEnvelopeFiles {
public:
    GroupEnvelopeFiles(GroupEnvelopeEncryptor& encryptor, const core::Connection& connection);

    // A new handle, `label` in the HandleManager, over `state`.
    FileHandle open(const std::string& label, EnvelopeFileState state);
    core::Buffer encryptChunk(FileHandle fileHandle, const core::Buffer& plainChunk);
    core::Buffer decryptChunk(FileHandle fileHandle, const core::Buffer& cipherChunk);
    CipherOffset seek(FileHandle fileHandle, FilePosition position);
    // Shared tail of both finishers: completeness check, then close and release whatever the outcome.
    EnvelopeFileState finish(FileHandle fileHandle, bool wantReading);
    // A handle used after this reports "not an open encrypted-file handle".
    void clear();

private:
    std::shared_ptr<EnvelopeFile> get(FileHandle fileHandle, bool wantReading);
    void release(FileHandle fileHandle);
    // The caller holds the handle's lock.
    core::Buffer drainChunks(EnvelopeFileState& state);

    GroupEnvelopeEncryptor& _encryptor;
    const core::Connection& _connection;
    privmx::utils::ThreadSaveMap<int64_t, std::shared_ptr<EnvelopeFile>> _files;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_ENVELOPE_GROUPENVELOPEFILES_HPP_
