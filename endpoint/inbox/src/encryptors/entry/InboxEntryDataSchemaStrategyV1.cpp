/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/crypto/ecc/ECC.hpp>
#include <privmx/endpoint/core/CoreConstants.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/store/StoreApiImpl.hpp>
#include <privmx/utils/Utils.hpp>

#include "privmx/endpoint/inbox/InboxException.hpp"
#include "privmx/endpoint/inbox/encryptors/entry/InboxEntryDataSchemaStrategyV1.hpp"

using namespace privmx;
using namespace privmx::endpoint;
using namespace privmx::endpoint::inbox;

InboxEntryDataSchemaStrategyV1::InboxEntryDataSchemaStrategyV1(
    const std::shared_ptr<ServerApi>& serverApi,
    const store::StoreApi& storeApi
)
    : _serverApi(serverApi), _storeApi(storeApi) {}

std::string InboxEntryDataSchemaStrategyV1::encrypt(
    const InboxEntrySendModel& data,
    privmx::crypto::PrivateKey& userPriv,
    privmx::crypto::PublicKey& inboxPub
) const {
    return _encryptor.encrypt(data, userPriv, inboxPub);
}

InboxEntryDataResult InboxEntryDataSchemaStrategyV1::decrypt(
    std::string& data,
    privmx::crypto::PrivateKey& inboxPriv
) const {
    return _encryptor.decrypt(data, inboxPriv);
}

InboxEntryPublicDataResult InboxEntryDataSchemaStrategyV1::decryptPublicOnly(std::string& data) const {
    return _encryptor.decryptPublicOnly(data);
}

InboxEntryResult InboxEntryDataSchemaStrategyV1::decryptEntry(
    const thread::server::Message& message,
    const core::ModuleKeys& inboxKeys,
    const std::shared_ptr<core::KeyProvider>& keyProvider
) const {
    InboxEntryResult result;
    result.statusCode = 0;
    try {
        inbox::server::InboxMessageServer inboxMessageServer;
        try {
            inboxMessageServer = inbox::server::InboxMessageServer::deserialize(utils::Base64::toString(message.data));
        } catch (...) { throw FailedToExtractMessagePublicMetaException(); }
        auto msgData = inboxMessageServer.message;

        auto msgPublicData = decryptPublicOnly(msgData);
        core::KeyDecryptionAndVerificationRequest keyProviderRequest;
        core::EncKeyLocation location{.contextId = inboxKeys.contextId, .resourceId = inboxKeys.moduleResourceId};
        keyProviderRequest.addOne(inboxKeys.keys, msgPublicData.usedInboxKeyId, location);
        auto encKey = keyProvider->getKeysAndVerify(keyProviderRequest).at(location).at(msgPublicData.usedInboxKeyId);
        auto eccKey = crypto::ECC::fromPrivateKey(encKey.key);
        auto privKeyECC = crypto::PrivateKey(eccKey);
        auto decrypted = decrypt(msgData, privKeyECC);
        result.statusCode = encKey.statusCode;
        result.publicData = decrypted.publicData;
        result.privateData = decrypted.privateData;
        result.storeId = inboxMessageServer.store;
        result.filesIds = inboxMessageServer.files;
        return result;
    } catch (const core::Exception& e) {
        return makeEmptyResultWithStatusCode(e.getCode());
    } catch (const privmx::utils::PrivmxException& e) {
        return makeEmptyResultWithStatusCode(core::ExceptionConverter::convert(e).getCode());
    } catch (...) { return makeEmptyResultWithStatusCode(ENDPOINT_CORE_EXCEPTION_CODE); }
}

inbox::InboxEntry InboxEntryDataSchemaStrategyV1::convertToFinal(
    const thread::server::Message& message,
    const InboxEntryResult& raw,
    const std::string& inboxId
) const {
    inbox::InboxEntry result;
    result.entryId = message.id;
    result.inboxId = inboxId;
    result.createDate = message.createDate;
    result.data = core::Buffer::from(raw.privateData.text);
    result.authorPubKey = raw.publicData.userPubKey;
    result.statusCode = raw.statusCode;
    if (raw.statusCode == 0) {
        try {
            core::DecryptedEncKey fileMetaEncKey{
                core::EncKey{.id = "", .key = raw.privateData.filesMetaKey},
                core::DecryptedVersionedData{.dataStructureVersion = 0, .statusCode = 0}
            };
            store::server::StoreFileGetManyModel filesGetModel;
            filesGetModel.storeId = raw.storeId;
            filesGetModel.fileIds = raw.filesIds;
            filesGetModel.failOnError = false;
            auto serverFiles{_serverApi->storeFileGetMany(filesGetModel)};
            for (auto file : serverFiles.files) {
                if (!file.error.has_value()) {
                    result.files.push_back(
                        std::get<0>(_storeApi.getImpl()->getFileMetaDataSchemaMapper().decrypt(file, fileMetaEncKey))
                    );
                } else {
                    store::File error;
                    auto e = FileFetchFailedException();
                    error.statusCode = e.getCode();
                    result.files.push_back(error);
                }
            }
        } catch (const core::Exception& e) {
            result.statusCode = e.getCode();
        } catch (const privmx::utils::PrivmxException& e) {
            result.statusCode = core::ExceptionConverter::convert(e).getCode();
        } catch (...) { result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE; }
    }
    result.schemaVersion = EntryDataSchema::Version::VERSION_1;
    return result;
}

InboxEntryResult InboxEntryDataSchemaStrategyV1::makeEmptyResultWithStatusCode(int64_t statusCode) {
    InboxEntryResult result;
    result.statusCode = statusCode;
    return result;
}
