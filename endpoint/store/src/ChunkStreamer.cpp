/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/ChunkStreamer.hpp"

#include <Poco/ByteOrder.h>
#include <memory>

#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/store/RequestApi.hpp"
#include "privmx/endpoint/store/StoreException.hpp"
#include "privmx/endpoint/store/StoreTypes.hpp"
#include <privmx/crypto/Crypto.hpp>

using namespace privmx::endpoint::store;

ChunkStreamer::ChunkStreamer(
    const std::shared_ptr<store::RequestApi>& requestApi,
    size_t chunkSize,
    uint64_t fileSize,
    size_t serverRequestChunkSize
)
    : _requestApi(requestApi), _chunkSize(chunkSize), _fileSize(fileSize),
      _chunkBufferedStream(serverRequestChunkSize) {}

void ChunkStreamer::createRequest(bool randomWriteSupport) {
    _key = core::CryptoSuite::randomBytes(32);
    auto size = getFileSize();
    server::FileDefinition fileDefinition{};
    fileDefinition.size = size.size;
    fileDefinition.checksumSize = size.checksumSize;
    fileDefinition.randomWrite = randomWriteSupport;
    server::CreateRequestModel createRequestModel{};
    createRequestModel.files = {fileDefinition};
    _fileIndex = 0;
    auto createRequestResult = _requestApi->createRequest(createRequestModel);
    _requestId = createRequestResult.id;
}

void ChunkStreamer::setRequestData(const std::string& requestId, const std::string& key, const uint64_t& fileIndex) {
    _requestId = requestId;
    _key = key;
    _fileIndex = fileIndex;
}

void ChunkStreamer::sendChunk(const std::string& data) {
    if (data.size() != _chunkSize) {
        throw InvalidFileChunkSizeException();
    }
    _uploadedFileSize += data.length();
    prepareAndSendChunk(data);
}

ChunksSentInfo ChunkStreamer::finalize(const std::string& data) {
    _uploadedFileSize += data.length();
    if (!data.empty()) {
        prepareAndSendChunk(data);
    }
    if (_uploadedFileSize + data.length() < _fileSize) {
        throw core::DataSmallerThanDeclaredException();
    }
    commitFile();
    return {
        // Znacznik formatu laduje w wewnetrznym meta pliku i to po nim odczyt dobiera `FileCipher`.
        .cipherType = _cipher.type(),
        .key = _key,
        .hmac = _cipher.topHash(_key, _checksums),
        .chunkSize = _chunkSize,
        .requestId = _requestId
    };
}

void ChunkStreamer::prepareAndSendChunk(const std::string& data) {
    if (_dataProcessed + static_cast<uint64_t>(data.size()) > _fileSize) {
        throw InvalidFileChunkSizeException();
    }

    auto encrypted = prepareChunk(data);
    _checksums.append(encrypted.hmac);

    _chunkBufferedStream.write(encrypted.data);

    sendFullChunksWhileCollected();

    _dataProcessed += data.size();
    ++_seq;
}

FileSizeResult ChunkStreamer::getFileSize() const {
    if (_fileSize == 0) {
        return {.size = 0, .checksumSize = 0};
    }
    const uint64_t parts = (_fileSize + _chunkSize - 1) / _chunkSize;
    return {
        .size = _cipher.encryptedFileSize(_fileSize, _chunkSize),
        .checksumSize = parts * _cipher.hashLength()
    };
}
ChunkStreamer::PreparedChunk ChunkStreamer::prepareChunk(const std::string& data) {
    // Ten sam format co przy odczycie - `FileCipher` jest jedynym miejscem, ktore go zna.
    // Wczesniej byla tu kopia logiki z `ChunkEncryptor`, czyli dwa miejsca do utrzymania zgodnymi.
    const auto chunk = _cipher.encryptChunk(_cipher.chunkKey(_key, _seq), data);
    return {.data = chunk.data, .hmac = chunk.hmac};
}

void ChunkStreamer::commitFile() {
    sendFullChunksWhileCollected();
    sendLastChunkIfNonEmpty();
    server::CommitFileModel commitFileModel{};
    commitFileModel.requestId = _requestId;
    commitFileModel.fileIndex = _fileIndex;
    commitFileModel.seq = _serverSeq;
    commitFileModel.checksum = _checksums;
    _requestApi->commitFile(commitFileModel);
}

std::string ChunkStreamer::getSeqBE() {
    uint32_t seq_be = Poco::ByteOrder::toBigEndian(_seq);
    return std::string((char*)&seq_be, 4);
}

void ChunkStreamer::sendFullChunksWhileCollected() {
    const uint64_t n = _chunkBufferedStream.getNumberOfFullChunks();
    for (uint64_t i = 0; i < n; i++) {
        sendChunkToServer(_chunkBufferedStream.getFullChunk(i));
    }
    if (n > 0) {
        _chunkBufferedStream.freeFullChunks();
    }
}

void ChunkStreamer::sendLastChunkIfNonEmpty() {
    if (!_chunkBufferedStream.isEmpty()) {
        sendChunkToServer(_chunkBufferedStream.readChunk());
    }
}

void ChunkStreamer::sendChunkToServer(std::string&& data) {
    server::ChunkModel chunkModel{};
    chunkModel.requestId = _requestId;
    chunkModel.fileIndex = _fileIndex;
    chunkModel.seq = _serverSeq;
    chunkModel.data = Pson::BinaryString(std::move(data));
    _requestApi->sendChunk(chunkModel);
    ++_serverSeq;
}

uint64_t ChunkStreamer::getUploadedFileSize() {
    return _uploadedFileSize;
}