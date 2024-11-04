/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/ChunkStreamer.hpp"

#include <memory>
#include <Poco/ByteOrder.h>

#include <privmx/crypto/Crypto.hpp>
#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/store/RequestApi.hpp"
#include "privmx/endpoint/store/StoreException.hpp"
#include "privmx/endpoint/store/StoreTypes.hpp"

using namespace privmx::endpoint::store;

ChunkStreamer::ChunkStreamer(const std::shared_ptr<store::RequestApi>& requestApi, size_t chunkSize, uint64_t fileSize, size_t serverRequestChunkSize)
            : _requestApi(requestApi), _chunkSize(chunkSize), _fileSize(fileSize), _chunkBufferedStream(serverRequestChunkSize) {}

void ChunkStreamer::createRequest() {
    _key = privmx::crypto::Crypto::randomBytes(32);
    auto size = getFileSize();
    auto createRequestModel = utils::TypedObjectFactory::createNewObject<server::CreateRequestModel>();
    auto fileDefinitions = utils::TypedObjectFactory::createNewList<server::FileDefinition>();
    auto fileDefinition = utils::TypedObjectFactory::createNewObject<server::FileDefinition>();
    fileDefinition.size(size.size);
    fileDefinition.checksumSize(size.checksumSize);
    fileDefinitions.add(fileDefinition);
    createRequestModel.files(fileDefinitions);
    _fileIndex = 0;
    auto createRequestResult = _requestApi->createRequest(createRequestModel);
    _requestId = createRequestResult.id();
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
    if(_uploadedFileSize + data.length() < _fileSize) {
        throw core::DataSmallerThanDeclaredException();
    }
    commitFile();
    return {
        .cipherType = 1,
        .key = _key,
        .hmac = privmx::crypto::Crypto::hmacSha256(_key, _checksums),
        .chunkSize = _chunkSize,
        .requestId = _requestId
    };
}

void ChunkStreamer::prepareAndSendChunk(const std::string& data) {
    if (_dataProcessed + static_cast<Poco::Int64>(data.size()) > _fileSize) {
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
        return {
            .size = 0,
            .checksumSize = 0
        };
    }
    uint64_t parts = (_fileSize + _chunkSize - 1) / _chunkSize;
    uint64_t lastChunkSize = _fileSize % _chunkSize;
    if (lastChunkSize == 0) {
        lastChunkSize = _chunkSize;
    }
    uint64_t fullChunkPaddingSize = CHUNK_PADDING - (_chunkSize % CHUNK_PADDING);
    uint64_t lastChunkPaddingSize = CHUNK_PADDING - (lastChunkSize % CHUNK_PADDING);
    uint64_t serverFileSize = (parts - 1) * (_chunkSize + HMAC_SIZE + IV_SIZE + fullChunkPaddingSize) + lastChunkSize + HMAC_SIZE + IV_SIZE + lastChunkPaddingSize;
    return {
        .size = serverFileSize,
        .checksumSize = parts * HMAC_SIZE
    };
}
ChunkStreamer::PreparedChunk ChunkStreamer::prepareChunk(const std::string& data) {
    std::string chunkKey = privmx::crypto::Crypto::sha256(_key + getSeqBE());
    std::string iv = privmx::crypto::Crypto::randomBytes(IV_SIZE);
    std::string cipher = privmx::crypto::Crypto::aes256CbcPkcs7Encrypt(data, chunkKey, iv);
    std::string ivWithCipher = iv + cipher;
    std::string hmac = privmx::crypto::Crypto::hmacSha256(chunkKey, ivWithCipher);
    return {
        .data = hmac + ivWithCipher,
        .hmac = hmac
    };
}

void ChunkStreamer::commitFile() {
    sendFullChunksWhileCollected();
    sendLastChunkIfNonEmpty();
    server::CommitFileModel commitFileModel = utils::TypedObjectFactory::createNewObject<server::CommitFileModel>();
    commitFileModel.requestId(_requestId);
    commitFileModel.fileIndex(_fileIndex);
    commitFileModel.seq(_serverSeq);
    commitFileModel.checksum(_checksums);
    _requestApi->commitFile(commitFileModel);
}

std::string ChunkStreamer::getSeqBE() {
    uint32_t seq_be = Poco::ByteOrder::toBigEndian(_seq);
    return std::string((char *)&seq_be, 4);
}

void ChunkStreamer::sendFullChunksWhileCollected() {
    const uint64_t n = _chunkBufferedStream.getNumberOfFullChunks();
    for(uint64_t i = 0; i < n; i++) {
        sendChunkToServer(_chunkBufferedStream.getFullChunk(i));
    }
    if(n > 0) {
        _chunkBufferedStream.freeFullChunks();
    }
}

void ChunkStreamer::sendLastChunkIfNonEmpty() {
    if (!_chunkBufferedStream.isEmpty()) {
        sendChunkToServer(_chunkBufferedStream.readChunk());
    }
}

void ChunkStreamer::sendChunkToServer(std::string&& data) {
    server::ChunkModel chunkModel = utils::TypedObjectFactory::createNewObject<server::ChunkModel>();
    chunkModel.requestId(_requestId);
    chunkModel.fileIndex(_fileIndex);
    chunkModel.seq(_serverSeq);
    chunkModel.data(Pson::BinaryString(std::move(data)));
    _requestApi->sendChunk(chunkModel);
    ++_serverSeq;
}

Poco::UInt64 ChunkStreamer::getUploadedFileSize() {
    return _uploadedFileSize;
}