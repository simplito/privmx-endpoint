/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/group/encryptors/envelope/GroupEnvelopeFiles.hpp"

#include <algorithm>
#include <mutex>

#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/CoreException.hpp>

#include "privmx/endpoint/group/GroupException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::group;

namespace {
constexpr const char* NOT_AN_OPEN_FILE_HANDLE = "field:fileHandle is not an open encrypted-file handle";

// For a call holding the handle's lock: a finish that won the lock first has closed it.
EnvelopeFileState& openState(EnvelopeFile& file) {
    if (file.state.closed) {
        throw core::InvalidParamsException(NOT_AN_OPEN_FILE_HANDLE);
    }
    return file.state;
}
} // namespace

GroupEnvelopeFiles::GroupEnvelopeFiles(GroupEnvelopeEncryptor& encryptor, const core::Connection& connection)
    : _encryptor(encryptor), _connection(connection) {}

FileHandle GroupEnvelopeFiles::open(const std::string& label, EnvelopeFileState state) {
    FileHandle handle = _connection.getImpl()->getHandleManager()->createHandle(label);
    auto file = std::make_shared<EnvelopeFile>();
    file->state = std::move(state);
    _files.set(handle, file);
    return handle;
}

void GroupEnvelopeFiles::clear() {
    _files.clear();
}

// `reading` never changes after construction, so it is checked here without the handle's lock.
std::shared_ptr<EnvelopeFile> GroupEnvelopeFiles::get(FileHandle fileHandle, bool wantReading) {
    auto file = _files.get(fileHandle);
    if (!file.has_value()) {
        throw core::InvalidParamsException(NOT_AN_OPEN_FILE_HANDLE);
    }
    if (file.value()->state.reading != wantReading) {
        throw core::InvalidParamsException(
            wantReading ? "field:fileHandle came from beginFileEncryption, not beginFileDecryption" :
                          "field:fileHandle came from beginFileDecryption, not beginFileEncryption"
        );
    }
    return file.value();
}

void GroupEnvelopeFiles::release(FileHandle fileHandle) {
    _files.erase(fileHandle);
    // Both, always. Dropping only the local entry leaks the id in HandleManager's map for the process
    // lifetime — the pair Store's FileHandleManager keeps together for the same reason.
    _connection.getImpl()->getHandleManager()->removeHandle(fileHandle);
}

// A chunk's sealed length follows from the declared size, so both directions work at arbitrary caller-chosen
// block sizes. Declaring the size up front is what distinguishes a short final chunk from one still arriving.
core::Buffer GroupEnvelopeFiles::drainChunks(EnvelopeFileState& state) {
    const ByteCount chunks = GroupEnvelopeEncryptor::chunkCount(state.plainSize);
    std::string out;
    while (state.index < chunks) {
        const ByteCount plainLen = GroupEnvelopeEncryptor::plainChunkSizeAt(state.plainSize, state.index);
        const ByteCount need = state.reading ? encryptedChunkSizeFor(plainLen) : plainLen;
        if (state.buffer.size() < need) {
            break;
        }
        core::Buffer piece = core::Buffer::from(state.buffer.substr(0, need));
        std::string produced = (state.reading ? _encryptor.decryptChunk(piece, state.fileKey, state.index) :
                                                _encryptor.encryptChunk(piece, state.fileKey, state.index))
                                   .stdString();
        if (state.skipInChunk > 0) {
            // A seek can land mid-chunk, but a chunk only opens whole. Drop the head the caller did not ask
            // for, once, on the first chunk after the seek.
            produced.erase(0, std::min<std::size_t>(state.skipInChunk, produced.size()));
            state.skipInChunk = 0;
        }
        out.append(produced);
        state.buffer.erase(0, need);
        state.index++;
    }
    // Past the last chunk nothing drains, so leftovers only grow. Refused here rather than at the close, or a
    // long ciphertext against a short declared size buffers the whole remainder first. Seeked readers included.
    if (state.reading && state.index >= chunks && !state.buffer.empty()) {
        throw InvalidEnvelopeFormatException("more file data than the declared size accounts for");
    }
    return core::Buffer::from(out);
}

core::Buffer GroupEnvelopeFiles::encryptChunk(FileHandle fileHandle, const core::Buffer& plainChunk) {
    auto file = get(fileHandle, false);
    std::lock_guard lock(file->mutex);
    EnvelopeFileState& state = openState(*file);
    if (state.written + plainChunk.size() > state.plainSize) {
        throw core::InvalidParamsException("field:plainChunk would exceed the declared file size");
    }
    state.written += plainChunk.size();
    state.buffer.append(plainChunk.stdString());
    return drainChunks(state);
}

core::Buffer GroupEnvelopeFiles::decryptChunk(FileHandle fileHandle, const core::Buffer& cipherChunk) {
    auto file = get(fileHandle, true);
    std::lock_guard lock(file->mutex);
    EnvelopeFileState& state = openState(*file);
    state.buffer.append(cipherChunk.stdString());
    return drainChunks(state);
}

CipherOffset GroupEnvelopeFiles::seek(FileHandle fileHandle, FilePosition position) {
    auto file = get(fileHandle, true);
    std::lock_guard lock(file->mutex);
    EnvelopeFileState& state = openState(*file);
    if (position < 0 || static_cast<ByteCount>(position) > state.plainSize) {
        throw core::InvalidParamsException("field:position is outside the file");
    }
    const ByteCount target = static_cast<ByteCount>(position);
    state.index = static_cast<ChunkIndex>(target / GroupEnvelopeEncryptor::CHUNK_SIZE);
    state.skipInChunk = target % GroupEnvelopeEncryptor::CHUNK_SIZE;
    // Whatever was half-collected belonged to the old position.
    state.buffer.clear();
    // From here on the caller decides what to read, so "did all of it arrive" is a question this handle can
    // no longer answer. `finishFileDecryption` reports that rather than pretending otherwise.
    state.seeked = true;
    return static_cast<int64_t>(GroupEnvelopeEncryptor::cipherOffsetOfChunk(state.index));
}

EnvelopeFileState GroupEnvelopeFiles::finish(FileHandle fileHandle, bool wantReading) {
    auto file = get(fileHandle, wantReading);
    std::lock_guard lock(file->mutex);
    EnvelopeFileState& state = openState(*file);
    // Closed whatever the outcome, so neither a second finish nor a chunk call still waiting for the lock
    // touches the state after this one.
    state.closed = true;
    // Free the handle however this ends, rather than hold a key resident because a file turned out short.
    // `Release` takes only the map and HandleManager locks; nothing takes those and then a file lock.
    struct Release {
        GroupEnvelopeFiles* self;
        int64_t handle;
        // This destructor exists to run during exception unwinding, so it must not throw out of one.
        ~Release() {
            try {
                self->release(handle);
            } catch (...) {}
        }
    } release{this, fileHandle};

    switch (GroupEnvelopeEncryptor::classifyRead(
        state.seeked, state.index, GroupEnvelopeEncryptor::chunkCount(state.plainSize), state.buffer.empty()
    )) {
    case GroupEnvelopeEncryptor::ReadOutcome::Truncated:
        // Every chunk authenticates itself, but nothing in chunk N says how many were meant to follow. The
        // declared size is the only place a dropped tail — or an unfinished write — shows up.
        throw EnvelopeTruncatedFileException();
    case GroupEnvelopeEncryptor::ReadOutcome::Overrun:
        // Every chunk the declared size called for arrived, and then more followed. `drainChunks` refuses
        // those as they arrive; this catches the caller who swallowed that and closed anyway.
        throw InvalidEnvelopeFormatException("more file data than the declared size accounts for");
    case GroupEnvelopeEncryptor::ReadOutcome::PartialRange:
    case GroupEnvelopeEncryptor::ReadOutcome::Complete:
        break;
    }
    // Moved, not copied, so the keys are not duplicated; `closed` (a bool, copied) stays set for anyone still
    // holding `file`.
    return std::move(state);
}
