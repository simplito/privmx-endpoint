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
#include <limits>
#include <mutex>

#include <privmx/crypto/Crypto.hpp>

#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/CoreException.hpp>

#include "privmx/endpoint/group/GroupException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::group;

EnvelopeFileState& GroupEnvelopeFiles::openState(EnvelopeFile& file) {
    if (file.state.closed) {
        throw core::InvalidParamsException(NOT_AN_OPEN_FILE_HANDLE);
    }
    return file.state;
}

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
    std::vector<int64_t> handles;
    _files.forAll([&](const int64_t& handle, const std::shared_ptr<EnvelopeFile>&) { handles.push_back(handle); });
    for (const int64_t handle : handles) {
        try {
            release(handle);
        } catch (...) {}
    }
}

Envelope GroupEnvelopeFiles::finishWrite(
    FileHandle fileHandle,
    const std::function<Envelope(const EnvelopeFileState&)>& seal
) {
    auto file = get(fileHandle, false);
    std::lock_guard lock(file->mutex);
    Envelope envelope = seal(openState(*file));
    file->state.closed = true;
    // `release` takes only the map and HandleManager locks; nothing takes those and then a file lock.
    release(fileHandle);
    return envelope;
}

void GroupEnvelopeFiles::abort(FileHandle fileHandle) {
    auto file = _files.get(fileHandle);
    if (!file.has_value()) {
        throw core::InvalidParamsException(NOT_AN_OPEN_FILE_HANDLE);
    }
    {
        std::lock_guard lock(file.value()->mutex);
        openState(*file.value()).closed = true;
    }
    release(fileHandle);
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

ByteCount GroupEnvelopeFiles::plainSizeOf(const EnvelopeFileState& state) {
    ByteCount size = 0;
    for (const FileChunk& chunk : state.chunks) {
        size += chunk.plainSize;
    }
    return size;
}

GroupEnvelopeFiles::Located GroupEnvelopeFiles::locate(const EnvelopeFileState& state, ByteCount position) {
    Located at{.index = 0, .plainStart = 0, .cipherStart = 0};
    // ponytail: a linear walk over the chunk list per call; keep prefix sums when files have millions of chunks.
    while (at.index < state.chunks.size() && at.plainStart + state.chunks[at.index].plainSize <= position) {
        at.plainStart += state.chunks[at.index].plainSize;
        at.cipherStart += encryptedChunkSizeFor(state.chunks[at.index].plainSize);
        at.index++;
    }
    return at;
}

// The sizes come from the envelope, so the ciphertext may arrive cut any way the caller likes. A chunk is
// checked against the digest the writer listed before it is opened: what comes out is what the writer sealed.
core::Buffer GroupEnvelopeFiles::drainChunks(EnvelopeFileState& state) {
    std::string out;
    while (state.index < state.chunks.size()) {
        const FileChunk& chunk = state.chunks[state.index];
        const ByteCount need = encryptedChunkSizeFor(chunk.plainSize);
        if (state.buffer.size() < need) {
            break;
        }
        const std::string piece = state.buffer.substr(0, need);
        if (privmx::crypto::Crypto::sha256(piece) != chunk.digest) {
            throw EnvelopeFileCorruptedException("chunk " + std::to_string(state.index));
        }
        std::string produced = _encryptor.decryptChunk(core::Buffer::from(piece), state.fileKey, state.index)
                                   .stdString();
        if (produced.size() != chunk.plainSize) {
            throw EnvelopeFileCorruptedException("chunk " + std::to_string(state.index));
        }
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
    // long ciphertext against a short list buffers the whole remainder first. Seeked readers included.
    if (state.index >= state.chunks.size() && !state.buffer.empty()) {
        throw InvalidEnvelopeFormatException("more file data than the envelope accounts for");
    }
    return core::Buffer::from(out);
}

// Every call seals what it was given, as chunks of at most CHUNK_SIZE: nothing is held back, so there is no
// tail for the caller to forget at the finish.
core::Buffer GroupEnvelopeFiles::encryptChunk(FileHandle fileHandle, const core::Buffer& plainChunk) {
    auto file = get(fileHandle, false);
    std::lock_guard lock(file->mutex);
    EnvelopeFileState& state = openState(*file);
    const std::string& plain = plainChunk.stdString();
    std::string out;
    for (std::size_t at = 0; at < plain.size(); at += GroupEnvelopeEncryptor::CHUNK_SIZE) {
        if (state.chunks.size() >= std::numeric_limits<ChunkIndex>::max()) {
            throw core::InvalidParamsException("field:plainChunk the file has too many chunks");
        }
        const std::string piece = plain.substr(at, GroupEnvelopeEncryptor::CHUNK_SIZE);
        const std::string sealed = _encryptor
                                       .encryptChunk(
                                           core::Buffer::from(piece), state.fileKey,
                                           static_cast<ChunkIndex>(state.chunks.size())
                                       )
                                       .stdString();
        state.chunks.push_back(
            FileChunk{
                .plainSize = static_cast<std::uint32_t>(piece.size()), .digest = privmx::crypto::Crypto::sha256(sealed)
            }
        );
        out.append(sealed);
    }
    return core::Buffer::from(out);
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
    if (position < 0 || static_cast<ByteCount>(position) > plainSizeOf(state)) {
        throw core::InvalidParamsException("field:position is outside the file");
    }
    const Located at = locate(state, static_cast<ByteCount>(position));
    state.index = at.index;
    state.skipInChunk = static_cast<ByteCount>(position) - at.plainStart;
    // Whatever was half-collected belonged to the old position.
    state.buffer.clear();
    // From here on the caller decides what to read, so "did all of it arrive" is a question this handle can
    // no longer answer. `finishFileDecryption` reports that rather than pretending otherwise.
    state.seeked = true;
    return static_cast<CipherOffset>(at.cipherStart);
}

CipherRange GroupEnvelopeFiles::cipherRange(FileHandle fileHandle, FilePosition from, FilePosition to) {
    auto file = get(fileHandle, true);
    std::lock_guard lock(file->mutex);
    const EnvelopeFileState& state = openState(*file);
    if (from < 0 || to < from || static_cast<ByteCount>(to) > plainSizeOf(state)) {
        throw core::InvalidParamsException("field:from..to is outside the file");
    }
    const Located first = locate(state, static_cast<ByteCount>(from));
    if (from == to) {
        return CipherRange{.offset = static_cast<int64_t>(first.cipherStart), .length = 0};
    }
    const Located last = locate(state, static_cast<ByteCount>(to) - 1);
    return CipherRange{
        .offset = static_cast<int64_t>(first.cipherStart),
        .length = static_cast<int64_t>(
            last.cipherStart + encryptedChunkSizeFor(state.chunks[last.index].plainSize) - first.cipherStart
        ),
    };
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

    if (!wantReading) {
        return std::move(state);
    }
    switch (
        GroupEnvelopeEncryptor::classifyRead(state.seeked, state.index, state.chunks.size(), state.buffer.empty())
    ) {
    case GroupEnvelopeEncryptor::ReadOutcome::Truncated:
        // Every chunk authenticates itself, but nothing in chunk N says how many were meant to follow. The
        // envelope is the only place a dropped tail — or an unfinished write — shows up.
        throw EnvelopeTruncatedFileException();
    case GroupEnvelopeEncryptor::ReadOutcome::Overrun:
        // Every chunk the envelope called for arrived, and then more followed. `drainChunks` refuses
        // those as they arrive; this catches the caller who swallowed that and closed anyway.
        throw InvalidEnvelopeFormatException("more file data than the envelope accounts for");
    case GroupEnvelopeEncryptor::ReadOutcome::PartialRange:
    case GroupEnvelopeEncryptor::ReadOutcome::Complete:
        break;
    }
    // Moved, not copied, so the keys are not duplicated; `closed` (a bool, copied) stays set for anyone still
    // holding `file`.
    return std::move(state);
}
