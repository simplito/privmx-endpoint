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
#include <privmx/endpoint/core/ExceptionConverter.hpp>
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
    try {
        std::shared_ptr<StreamApiImpl> impl(new StreamApiImpl(connection, groupApi));
        return StreamApi(impl);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
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
    try {
        return impl->createStreamRoom(
            contextId, users, managers, publicMeta, privateMeta, policies, emptyRoomTtl, groups
        );
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
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
    try {
        return impl->updateStreamRoom(
            streamRoomId, users, managers, publicMeta, privateMeta, version, force, forceGenerateNewKey, policies,
            groups
        );
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
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
    try {
        return impl->rotateStreamRoomKeys(streamRoomId, users, managers, version, force, groups);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

core::PagingList<StreamRoom> StreamApi::listStreamRooms(const std::string& contextId, const core::PagingQuery& query) {
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

StreamRoom StreamApi::getStreamRoom(const std::string& streamRoomId) {
    auto impl = getImpl();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    try {
        return impl->getStreamRoom(streamRoomId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::deleteStreamRoom(const std::string& streamRoomId) {
    auto impl = getImpl();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    try {
        return impl->deleteStreamRoom(streamRoomId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::vector<StreamInfo> StreamApi::listStreams(const std::string& streamRoomId) {
    auto impl = getImpl();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    try {
        return impl->listStreams(streamRoomId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::vector<StreamSubscriber> StreamApi::listStreamRoomParticipants(const std::string& streamRoomId) {
    auto impl = getImpl();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    try {
        return impl->listStreamRoomParticipants(streamRoomId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::joinStreamRoom(const std::string& streamRoomId) {
    auto impl = getImpl();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    try {
        return impl->joinStreamRoom(streamRoomId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::leaveStreamRoom(const std::string& streamRoomId) {
    auto impl = getImpl();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    try {
        return impl->leaveStreamRoom(streamRoomId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

StreamHandle StreamApi::createStream(const std::string& streamRoomId) {
    auto impl = getImpl();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    try {
        return impl->createStream(streamRoomId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::vector<AudioDevice> StreamApi::getAudioDevices() {
    auto impl = getImpl();
    try {
        return impl->getAudioDevices();
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::vector<VideoDevice> StreamApi::getVideoDevices() {
    auto impl = getImpl();
    try {
        return impl->getVideoDevices();
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::vector<DesktopDevice> StreamApi::getDesktopDevices(DesktopType desktopType) {
    auto impl = getImpl();
    try {
        return impl->getDesktopDevices(desktopType);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

MediaTrack StreamApi::addTrack(
    const StreamHandle& streamHandle,
    const MediaDevice& track,
    const MediaTrackConstrains& mediaTrackConstrains
) {
    auto impl = getImpl();
    try {
        return impl->addTrack(streamHandle, track, mediaTrackConstrains);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::removeTrack(const StreamHandle& streamHandle, const MediaDevice& track) {
    auto impl = getImpl();
    try {
        return impl->removeTrack(streamHandle, track);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

StreamPublishResult StreamApi::publishStream(const StreamHandle& streamHandle) {
    auto impl = getImpl();
    try {
        return impl->publishStream(streamHandle);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

StreamPublishResult StreamApi::updateStream(const StreamHandle& streamHandle) {
    auto impl = getImpl();
    try {
        return impl->updateStream(streamHandle);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::removeStream(const StreamHandle& streamHandle) {
    auto impl = getImpl();
    try {
        return impl->removeStream(streamHandle);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

SubscriberStreamHandle StreamApi::createSubscriberStream(

    const std::string& streamRoomId,
    const std::vector<StreamSubscription>& subscriptions
) {
    auto impl = getImpl();
    core::Validator::validateId(streamRoomId, "field:streamRoomId ");
    try {
        return impl->createSubscriberStream(streamRoomId, subscriptions);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::updateSubscriberStream(
    const SubscriberStreamHandle& subscriptionHandle,
    const std::vector<StreamSubscription>& subscriptionsToAdd,
    const std::vector<StreamSubscription>& subscriptionsToRemove
) {
    auto impl = getImpl();
    try {
        return impl->updateSubscriberStream(subscriptionHandle, subscriptionsToAdd, subscriptionsToRemove);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::removeSubscriberStream(const SubscriberStreamHandle& subscriptionHandle) {
    auto impl = getImpl();
    try {
        return impl->removeSubscriberStream(subscriptionHandle);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::vector<std::string> StreamApi::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    auto impl = getImpl();
    try {
        return impl->subscribeFor(subscriptionQueries);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    auto impl = getImpl();
    try {
        return impl->unsubscribeFrom(subscriptionIds);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string StreamApi::buildSubscriptionQuery(
    EventType eventType,
    EventSelectorType selectorType,
    const std::string& selectorId
) {
    auto impl = getImpl();
    try {
        return impl->buildSubscriptionQuery(eventType, selectorType, selectorId);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::dropBrokenFrames(const std::string& streamRoomId, bool enable) {
    auto impl = getImpl();
    try {
        return impl->dropBrokenFrames(streamRoomId, enable);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::addRemoteStreamListener(
    const std::string& streamRoomId,
    std::optional<int64_t> streamId,
    std::shared_ptr<OnTrackInterface> onTrack
) {
    auto impl = getImpl();
    try {
        return impl->addRemoteStreamListener(streamRoomId, streamId, onTrack);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

void StreamApi::sendData(const StreamHandle& streamHandle, core::Buffer data) {
    auto impl = getImpl();
    try {
        return impl->sendData(streamHandle, data);
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}