/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/stream/StreamApiLow.hpp"

#include "privmx/endpoint/stream/StreamApiLowImpl.hpp"
#include "privmx/endpoint/stream/StreamException.hpp"
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/EventVarSerializer.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/JsonSerializer.hpp>
#include <privmx/endpoint/core/Validator.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::stream;

StreamApiLow StreamApiLow::create(const core::Connection& connection, const std::optional<group::GroupApi>& groupApi) {
    std::shared_ptr<core::ConnectionImpl> connectionImpl = connection.getImpl();
    std::shared_ptr<StreamApiLowImpl> impl(new stream::StreamApiLowImpl(
        connection, connectionImpl->getGateway(), connectionImpl->getUserPrivKey(), connectionImpl->getKeyProvider(),
        connectionImpl->getHost(), connectionImpl->getEventMiddleware(), groupApi
    ));
    return StreamApiLow(impl);
}

StreamApiLow::StreamApiLow(const std::shared_ptr<StreamApiLowImpl>& impl) : BaseApiClass(impl) {}

std::vector<TurnCredentials> StreamApiLow::getTurnCredentials() {
    auto impl = getImpl();
    return impl->getTurnCredentials();
}

std::string StreamApiLow::createStreamRoom(
    const std::string& contextId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const std::optional<core::ContainerPolicyWithoutItem>& policies,
    const std::optional<int64_t>& emptyRoomTtl,
    const std::vector<core::GroupGrantWithKey>& groups
) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    core::Validator::validateClass<std::vector<core::GroupGrantWithKey>>(groups, "field:groups ");
    return impl->createStreamRoom(
        contextId, users, managers, publicMeta, privateMeta, policies, emptyRoomTtl, "stream", groups
    );
}

void StreamApiLow::updateStreamRoom(
    const std::string& streamRoomId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const int64_t version,
    const bool force,
    const bool forceGenerateNewKey,
    const std::optional<core::ContainerPolicyWithoutItem>& policies,
    const std::vector<core::GroupGrantWithKey>& groups
) {
    auto impl = getImpl();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    core::Validator::validateClass<std::vector<core::GroupGrantWithKey>>(groups, "field:groups ");
    return impl->updateStreamRoom(
        streamRoomId, users, managers, publicMeta, privateMeta, version, force, forceGenerateNewKey, policies, groups
    );
}

void StreamApiLow::rotateStreamRoomKeys(
    const std::string& streamRoomId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const int64_t version,
    const bool force,
    const std::vector<core::GroupGrantWithKey>& groups
) {
    auto impl = getImpl();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(users, "field:users ");
    core::Validator::validateClass<std::vector<core::UserWithPubKey>>(managers, "field:managers ");
    core::Validator::validateClass<std::vector<core::GroupGrantWithKey>>(groups, "field:groups ");
    impl->rotateStreamRoomKeys(streamRoomId, users, managers, version, force, groups);
}

core::PagingList<StreamRoom> StreamApiLow::listStreamRooms(
    const std::string& contextId,
    const core::PagingQuery& query
) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validatePagingQuery(query, {"createDate"}, "field:query ");
    return impl->listStreamRooms(contextId, query);
}

StreamRoom StreamApiLow::getStreamRoom(const std::string& streamRoomId) {
    auto impl = getImpl();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    return impl->getStreamRoom(streamRoomId);
}

void StreamApiLow::deleteStreamRoom(const std::string& streamRoomId) {
    auto impl = getImpl();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    return impl->deleteStreamRoom(streamRoomId);
}

std::vector<std::string> StreamApiLow::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    auto impl = getImpl();
    return impl->subscribeFor(subscriptionQueries);
}

void StreamApiLow::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    auto impl = getImpl();
    return impl->unsubscribeFrom(subscriptionIds);
}

std::string StreamApiLow::buildSubscriptionQuery(
    EventType eventType,
    EventSelectorType selectorType,
    const std::string& selectorId
) {
    auto impl = getImpl();
    return impl->buildSubscriptionQuery(eventType, selectorType, selectorId);
}

std::vector<StreamInfo> StreamApiLow::listStreams(const std::string& streamRoomId) {
    auto impl = getImpl();
    return impl->listStreams(streamRoomId);
}

std::vector<StreamSubscriber> StreamApiLow::listStreamRoomParticipants(const std::string& streamRoomId) {
    auto impl = getImpl();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    return impl->listStreamRoomParticipants(streamRoomId);
}

void StreamApiLow::joinStreamRoom(const std::string& streamRoomId, std::shared_ptr<WebRTCInterface> webRtc) {
    auto impl = getImpl();
    return impl->joinStreamRoom(streamRoomId, webRtc);
}

void StreamApiLow::leaveStreamRoom(const std::string& streamRoomId) {
    auto impl = getImpl();
    return impl->leaveStreamRoom(streamRoomId);
}

StreamHandle StreamApiLow::createStream(const std::string& streamRoomId) {
    auto impl = getImpl();
    return impl->createStream(streamRoomId);
}

StreamPublishResult StreamApiLow::publishStream(const StreamHandle& streamHandle) {
    auto impl = getImpl();
    return impl->publishStream(streamHandle);
}

StreamPublishResult StreamApiLow::updateStream(const StreamHandle& streamHandle) {
    auto impl = getImpl();
    return impl->updateStream(streamHandle);
}

void StreamApiLow::removeStream(const StreamHandle& streamHandle) {
    auto impl = getImpl();
    return impl->removeStream(streamHandle);
}

SubscriberStreamHandle StreamApiLow::createSubscriberStream(
    const std::string& streamRoomId,
    const std::vector<StreamSubscription>& subscriptions
) {
    auto impl = getImpl();
    return impl->createSubscriberStream(streamRoomId, subscriptions);
}

void StreamApiLow::updateSubscriberStream(
    const SubscriberStreamHandle& subscriptionHandle,
    const std::vector<StreamSubscription>& subscriptionsToAdd,
    const std::vector<StreamSubscription>& subscriptionsToRemove
) {
    auto impl = getImpl();
    return impl->updateSubscriberStream(subscriptionHandle, subscriptionsToAdd, subscriptionsToRemove);
}

void StreamApiLow::removeSubscriberStream(const SubscriberStreamHandle& subscriptionHandle) {
    auto impl = getImpl();
    return impl->removeSubscriberStream(subscriptionHandle);
}

void StreamApiLow::trickle(const int64_t sessionId, const std::string& candidateAsJson) {
    auto impl = getImpl();
    core::Validator::validateNumberPositive(sessionId, "field:sessionId ");
    return impl->trickle(sessionId, candidateAsJson);
}

void StreamApiLow::setNewOfferOnReconfigure(const int64_t sessionId, const SdpWithTypeModel& sdp) {
    auto impl = getImpl();
    core::Validator::validateNumberPositive(sessionId, "field:sessionId ");
    return impl->setNewOfferOnReconfigure(sessionId, sdp);
}

core::Buffer StreamApiLow::encryptDataChannelMessage(
    const std::string& streamRoomId,
    const DataChannelMessage& plainMessage
) {
    auto impl = getImpl();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    return impl->encryptDataChannelMessage(streamRoomId, plainMessage);
}

DecryptedDataChannelMessage StreamApiLow::decryptDataChannelMessage(
    const std::string& streamRoomId,
    const std::string& remoteStreamId,
    const core::Buffer& encryptedMessage
) {
    auto impl = getImpl();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    return impl->decryptDataChannelMessage(streamRoomId, remoteStreamId, encryptedMessage);
}
