/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/stream/StreamApiLow.hpp"

#include <iostream>
#include <ostream>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/EventVarSerializer.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/JsonSerializer.hpp>
#include <privmx/endpoint/core/Validator.hpp>
#include <privmx/endpoint/event/EventApiImpl.hpp>


#include "privmx/endpoint/stream/StreamApiLowImpl.hpp"
#include "privmx/endpoint/stream/StreamException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::stream;

StreamApiLow StreamApiLow::create(
    const core::Connection& connection, 
    event::EventApi& eventApi,
    StreamEncryptionMode streamEncryptionMode
) {
    try {
        std::shared_ptr<core::ConnectionImpl> connectionImpl = connection.getImpl();
        std::shared_ptr<event::EventApiImpl> eventApiImpl = eventApi.getImpl();
        std::shared_ptr<StreamApiLowImpl> impl(new stream::StreamApiLowImpl(
            eventApiImpl,
            connection,
            connectionImpl->getGateway(),
            connectionImpl->getUserPrivKey(),
            connectionImpl->getKeyProvider(),
            connectionImpl->getHost(),
            connectionImpl->getEventMiddleware(),
            streamEncryptionMode
        ));
        impl->attach(impl);
        return StreamApiLow(impl);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

StreamApiLow::StreamApiLow() {};
StreamApiLow::StreamApiLow(const StreamApiLow& obj): ExtendedPointer(obj) {};
StreamApiLow& StreamApiLow::operator=(const StreamApiLow& obj) {
    this->ExtendedPointer::operator=(obj);
    return *this;
};
StreamApiLow::StreamApiLow(StreamApiLow&& obj): ExtendedPointer(std::move(obj)) {};
StreamApiLow::~StreamApiLow() {}
StreamApiLow::StreamApiLow(const std::shared_ptr<StreamApiLowImpl>& impl) : ExtendedPointer(impl) {}

std::vector<TurnCredentials> StreamApiLow::getTurnCredentials() {
    auto impl = getImpl();
    try {
        return impl->getTurnCredentials();
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string StreamApiLow::createStreamRoom(
    const std::string& contextId, 
    const std::vector<core::UserWithPubKey>& users, 
    const std::vector<core::UserWithPubKey>&managers,
    const core::Buffer& publicMeta, 
    const core::Buffer& privateMeta,
    const std::optional<core::ContainerPolicy>& policies
) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    try {
        return impl->createStreamRoom(contextId, users, managers, publicMeta, privateMeta, policies);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApiLow::updateStreamRoom(
    const std::string& streamRoomId, 
    const std::vector<core::UserWithPubKey>& users, 
    const std::vector<core::UserWithPubKey>&managers,
    const core::Buffer& publicMeta, 
    const core::Buffer& privateMeta, 
    const int64_t version, 
    const bool force, 
    const bool forceGenerateNewKey, 
    const std::optional<core::ContainerPolicy>& policies
) {
    auto impl = getImpl();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    try {
        return impl->updateStreamRoom(streamRoomId, users, managers, publicMeta, privateMeta, version, force, forceGenerateNewKey, policies);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::PagingList<StreamRoom> StreamApiLow::listStreamRooms(const std::string& contextId, const core::PagingQuery& query) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validatePagingQuery(query, {"createDate"}, "field:query ");
    try {
        return impl->listStreamRooms(contextId, query);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

StreamRoom StreamApiLow::getStreamRoom(const std::string& streamRoomId) {
    auto impl = getImpl();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    try {
        return impl->getStreamRoom(streamRoomId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApiLow::deleteStreamRoom(const std::string& streamRoomId) {
    auto impl = getImpl();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    try {
        return impl->deleteStreamRoom(streamRoomId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::vector<std::string> StreamApiLow::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    auto impl = getImpl();
    try {
        return impl->subscribeFor(subscriptionQueries);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApiLow::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    auto impl = getImpl();
    try {
        return impl->unsubscribeFrom(subscriptionIds);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string StreamApiLow::buildSubscriptionQuery(EventType eventType, EventSelectorType selectorType, const std::string& selectorId) {
    auto impl = getImpl();
    try {
        return impl->buildSubscriptionQuery(eventType, selectorType, selectorId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::vector<StreamInfo> StreamApiLow::listStreams(const std::string& streamRoomId) {
    auto impl = getImpl();
    try {
        return impl->listStreams(streamRoomId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApiLow::joinStreamRoom(const std::string& streamRoomId, std::shared_ptr<WebRTCInterface> webRtc) {
    auto impl = getImpl();
    try {
        return impl->joinStreamRoom(streamRoomId, webRtc);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApiLow::leaveStreamRoom(const std::string& streamRoomId) {
    auto impl = getImpl();
    try {
        return impl->leaveStreamRoom(streamRoomId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApiLow::enableStreamRoomRecording(const std::string& streamRoomId) {
    auto impl = getImpl();
    try {
        return impl->enableStreamRoomRecording(streamRoomId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::vector<stream::RecordingEncKey> StreamApiLow::getStreamRoomRecordingKeys(const std::string& streamRoomId) {
    auto impl = getImpl();
    try {
        return impl->getStreamRoomRecordingKeys(streamRoomId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

StreamHandle StreamApiLow::createStream(const std::string& streamRoomId) {
    auto impl = getImpl();
    try {
        return impl->createStream(streamRoomId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

StreamPublishResult StreamApiLow::publishStream(const StreamHandle& streamHandle) {
    auto impl = getImpl();
    try {
        return impl->publishStream(streamHandle);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

StreamPublishResult StreamApiLow::updateStream(const StreamHandle& streamHandle) {
    auto impl = getImpl();
    try {
        return impl->updateStream(streamHandle);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApiLow::unpublishStream(const StreamHandle& streamHandle) {
    auto impl = getImpl();
    try {
        return impl->unpublishStream(streamHandle);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApiLow::subscribeToRemoteStreams(const std::string& streamRoomId, const std::vector<StreamSubscription>& subscriptions) {
    auto impl = getImpl();
    try {
        return impl->subscribeToRemoteStreams(streamRoomId, subscriptions);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApiLow::modifyRemoteStreamsSubscriptions(const std::string& streamRoomId, const std::vector<StreamSubscription>& subscriptionsToAdd, const std::vector<StreamSubscription>& subscriptionsToRemove) {
    auto impl = getImpl();
    try {
        return impl->modifyRemoteStreamsSubscriptions(streamRoomId, subscriptionsToAdd, subscriptionsToRemove);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApiLow::unsubscribeFromRemoteStreams(const std::string& streamRoomId, const std::vector<StreamSubscription>& subscriptionsToRemove) {
    auto impl = getImpl();
    try {
        return impl->unsubscribeFromRemoteStreams(streamRoomId, subscriptionsToRemove);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApiLow::keyManagement(const std::string& streamRoomId, bool disable) {
    auto impl = getImpl();
    try {
        return impl->keyManagement(streamRoomId, disable);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApiLow::trickle(const int64_t sessionId, const std::string& candidateAsJson) {
    auto impl = getImpl();
    core::Validator::validateNumberPositive(sessionId, "field:sessionId ");
    try {
        return impl->trickle(sessionId, candidateAsJson);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApiLow::acceptOfferOnReconfigure(const int64_t sessionId, const SdpWithTypeModel& sdp) {
    auto impl = getImpl();
    core::Validator::validateNumberPositive(sessionId, "field:sessionId ");
    try {
        return impl->acceptOfferOnReconfigure(sessionId, sdp);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApiLow::setNewOfferOnReconfigure(const int64_t sessionId, const SdpWithTypeModel& sdp) {
    auto impl = getImpl();
    core::Validator::validateNumberPositive(sessionId, "field:sessionId ");
    try {
        return impl->setNewOfferOnReconfigure(sessionId, sdp);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::Buffer StreamApiLow::encryptDataChannelMessage(const std::string& streamRoomId, const DataChannelMessage& plainMessage) {
    auto impl = getImpl();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    try {
        return impl->encryptDataChannelMessage(streamRoomId, plainMessage);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApiLow::registerRemoteDataChannel(const std::string& streamRoomId, const std::string& remoteStreamId) {
    auto impl = getImpl();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    try {
        return impl->registerRemoteDataChannel(streamRoomId, remoteStreamId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

DecryptedDataChannelMessage StreamApiLow::decryptDataChannelMessage(const std::string& streamRoomId, const std::string& remoteStreamId, const core::Buffer& encryptedMessage) {
    auto impl = getImpl();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    try {
        return impl->decryptDataChannelMessage(streamRoomId, remoteStreamId, encryptedMessage);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}
