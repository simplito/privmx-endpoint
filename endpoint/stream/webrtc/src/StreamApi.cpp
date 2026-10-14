/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/stream/StreamApi.hpp"
#include "privmx/endpoint/stream/StreamApiImpl.hpp"
#include "privmx/endpoint/stream/StreamException.hpp"
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/EventVarSerializer.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/JsonSerializer.hpp>
#include <privmx/endpoint/core/Validator.hpp>
#include <privmx/endpoint/event/EventApi.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::stream;

StreamApi StreamApi::create(
    core::Connection& connection,
    [[maybe_unused]] event::EventApi& _eventApi,
    const std::optional<group::GroupApi>& groupApi
) {
    std::shared_ptr<StreamApiImpl> impl(new StreamApiImpl(connection, groupApi));
    return StreamApi(impl);
}

StreamApi::StreamApi(const std::shared_ptr<StreamApiImpl>& impl) : BaseApiClass(impl) {}

std::string StreamApi::createStreamRoom(
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
    return impl->createStreamRoom(contextId, users, managers, publicMeta, privateMeta, policies, emptyRoomTtl, groups);
}

void StreamApi::updateStreamRoom(
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

void StreamApi::rotateStreamRoomKeys(
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
    return impl->rotateStreamRoomKeys(streamRoomId, users, managers, version, force, groups);
}

core::PagingList<StreamRoom> StreamApi::listStreamRooms(const std::string& contextId, const core::PagingQuery& query) {
    auto impl = getImpl();
    core::Validator::validateId(contextId, "field:contextId ");
    core::Validator::validatePagingQuery(query, {"createDate"}, "field:query ");
    return impl->listStreamRooms(contextId, query);
}

StreamRoom StreamApi::getStreamRoom(const std::string& streamRoomId) {
    auto impl = getImpl();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    return impl->getStreamRoom(streamRoomId);
}

void StreamApi::deleteStreamRoom(const std::string& streamRoomId) {
    auto impl = getImpl();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    return impl->deleteStreamRoom(streamRoomId);
}

std::vector<StreamInfo> StreamApi::listStreams(const std::string& streamRoomId) {
    auto impl = getImpl();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    return impl->listStreams(streamRoomId);
}

std::vector<StreamSubscriber> StreamApi::listStreamRoomParticipants(const std::string& streamRoomId) {
    auto impl = getImpl();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    return impl->listStreamRoomParticipants(streamRoomId);
}

void StreamApi::joinStreamRoom(const std::string& streamRoomId) {
    auto impl = getImpl();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    return impl->joinStreamRoom(streamRoomId);
}

void StreamApi::leaveStreamRoom(const std::string& streamRoomId) {
    auto impl = getImpl();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    return impl->leaveStreamRoom(streamRoomId);
}

StreamHandle StreamApi::createStream(const std::string& streamRoomId) {
    auto impl = getImpl();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    return impl->createStream(streamRoomId);
}

std::vector<AudioDevice> StreamApi::getAudioDevices() {
    auto impl = getImpl();
    return impl->getAudioDevices();
}

std::vector<VideoDevice> StreamApi::getVideoDevices() {
    auto impl = getImpl();
    return impl->getVideoDevices();
}

std::vector<DesktopDevice> StreamApi::getDesktopDevices(DesktopType desktopType) {
    auto impl = getImpl();
    return impl->getDesktopDevices(desktopType);
}

MediaTrack StreamApi::addTrack(
    const StreamHandle& streamHandle,
    const MediaDevice& track,
    const MediaTrackConstrains& mediaTrackConstrains
) {
    auto impl = getImpl();
    return impl->addTrack(streamHandle, track, mediaTrackConstrains);
}

void StreamApi::removeTrack(const StreamHandle& streamHandle, const MediaDevice& track) {
    auto impl = getImpl();
    return impl->removeTrack(streamHandle, track);
}

StreamPublishResult StreamApi::publishStream(const StreamHandle& streamHandle) {
    auto impl = getImpl();
    return impl->publishStream(streamHandle);
}

StreamPublishResult StreamApi::updateStream(const StreamHandle& streamHandle) {
    auto impl = getImpl();
    return impl->updateStream(streamHandle);
}

void StreamApi::removeStream(const StreamHandle& streamHandle) {
    auto impl = getImpl();
    return impl->removeStream(streamHandle);
}

SubscriberStreamHandle StreamApi::createSubscriberStream(

    const std::string& streamRoomId,
    const std::vector<StreamSubscription>& subscriptions
) {
    auto impl = getImpl();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    return impl->createSubscriberStream(streamRoomId, subscriptions);
}

void StreamApi::updateSubscriberStream(
    const SubscriberStreamHandle& subscriptionHandle,
    const std::vector<StreamSubscription>& subscriptionsToAdd,
    const std::vector<StreamSubscription>& subscriptionsToRemove
) {
    auto impl = getImpl();
    return impl->updateSubscriberStream(subscriptionHandle, subscriptionsToAdd, subscriptionsToRemove);
}

void StreamApi::removeSubscriberStream(const SubscriberStreamHandle& subscriptionHandle) {
    auto impl = getImpl();
    return impl->removeSubscriberStream(subscriptionHandle);
}

std::vector<std::string> StreamApi::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    auto impl = getImpl();
    return impl->subscribeFor(subscriptionQueries);
}

void StreamApi::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    auto impl = getImpl();
    return impl->unsubscribeFrom(subscriptionIds);
}

std::string StreamApi::buildSubscriptionQuery(
    EventType eventType,
    EventSelectorType selectorType,
    const std::string& selectorId
) {
    auto impl = getImpl();
    return impl->buildSubscriptionQuery(eventType, selectorType, selectorId);
}

void StreamApi::dropBrokenFrames(const std::string& streamRoomId, bool enable) {
    auto impl = getImpl();
    return impl->dropBrokenFrames(streamRoomId, enable);
}

void StreamApi::addRemoteStreamListener(
    const std::string& streamRoomId,
    std::optional<int64_t> streamId,
    std::shared_ptr<OnTrackInterface> onTrack
) {
    auto impl = getImpl();
    return impl->addRemoteStreamListener(streamRoomId, streamId, onTrack);
}

void StreamApi::sendData(const StreamHandle& streamHandle, core::Buffer data) {
    auto impl = getImpl();
    return impl->sendData(streamHandle, data);
}