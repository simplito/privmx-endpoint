/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/rpc/ConnectionManager.hpp>
#include <privmx/rpc/RpcUtils.hpp>
#include <privmx/rpc/RpcException.hpp>

using namespace privmx::rpc;

ConnectionManager::Ptr ConnectionManager::_instance = new ConnectionManager();

ConnectionManager::Ptr ConnectionManager::getInstance() {
    return _instance;
}

AuthorizedConnection::Ptr ConnectionManager::createEcdheConnection(const EcdheOptions& auth, const ConnectionOptions& options) {
    auto full_options = fillOptions(options);
    auto key = auth.key.value_or(crypto::PrivateKey::generateRandom());
    AuthorizedConnection::Ptr connection = new AuthorizedConnection(full_options);
    connection->ecdheConnect(key);
    connection->init();
    return connection;
}

AuthorizedConnection::Ptr ConnectionManager::createEcdhexConnection(const EcdhexOptions& auth, const ConnectionOptions& options) {
    auto full_options = fillOptions(options);
    AuthorizedConnection::Ptr connection = new AuthorizedConnection(full_options);
    connection->ecdhexConnect(auth.key, auth.solution);
    connection->init();
    return connection;
}

AuthorizedConnection::Ptr ConnectionManager::createSrpConnection(const SrpOptions& auth, const ConnectionOptions& options) {
    auto full_options = fillOptions(options);
    AuthorizedConnection::Ptr connection = new AuthorizedConnection(full_options);
    auto additional_login_step = connection->srpConnect(auth.username, auth.password, auth.properties);
    processAdditionalLoginStep(connection, additional_login_step, auth.on_additional_login_step);
    connection->init();
    return connection;
}

AuthorizedConnection::Ptr ConnectionManager::createKeyConnection(const KeyOptions& auth, const ConnectionOptions& options) {
    auto full_options = fillOptions(options);
    AuthorizedConnection::Ptr connection = new AuthorizedConnection(full_options);
    auto additional_login_step = connection->keyConnect(auth.key, auth.properties);
    processAdditionalLoginStep(connection, additional_login_step, auth.on_additional_login_step);
    connection->init();
    return connection;
}

AuthorizedConnection::Ptr ConnectionManager::createSessionConnection(const SessionRestoreOptionsEx& auth, const ConnectionOptions& options) {
    auto full_options = fillOptions(options);
    AuthorizedConnection::Ptr connection = new AuthorizedConnection(full_options);
    connection->sessionConnect(auth);
    connection->init();
    return connection;
}

PlainConnection::Ptr ConnectionManager::createPlainConnection(const ConnectionOptions& options) {
    auto full_options = fillOptions(options);
    AuthorizedConnection::Ptr connection = new AuthorizedConnection(full_options);
    PlainConnection::Ptr plain_connection = new PlainConnection(connection);
    return plain_connection;
}

void ConnectionManager::probe(const std::string& url, long timeout) {
    ConnectionOptions options;
    options.url = url;
    options.app_handler.default_timeout = timeout;
    options.host = Poco::URI(url).getHost();
    auto connection = createPlainConnection(options);
    auto res = connection->call("ping", Poco::JSON::Object::Ptr(new Poco::JSON::Object()));
    if (res != "pong") {
        throw ProbeFailException();
    }
}

void ConnectionManager::processAdditionalLoginStep(AuthorizedConnection::Ptr connection, Poco::JSON::Object::Ptr additional_login_step, std::optional<AdditionalLoginStepCallback> additional_login_step_callback) {
    if (additional_login_step.isNull() || !additional_login_step_callback.has_value() || !additional_login_step_callback.value()) return;
    SecondFactorServiceImpl::Ptr service = new SecondFactorServiceImpl(connection);
    additional_login_step_callback.value()(additional_login_step, service);
}

ConnectionOptionsFull ConnectionManager::fillOptions(const ConnectionOptions& options) {
    ConnectionOptionsFull res {
        .url = options.url,
        .host = options.host,
        .agent = options.agent.value_or("privmx-rpc-cpp"),
        .main_channel = options.main_channel.value_or(ChannelType::AJAX),
        .websocket = options.websocket.value_or(true),
        .websocket_options = {
            .connect_timeout = options.websocket_options.connect_timeout.value_or(5000),
            .ping_timeout = options.websocket_options.ping_timeout.value_or(5000),
            .on_heart_beat_callback = options.websocket_options.on_heart_beat_callback.value_or([]([[maybe_unused]] auto ignore){}),
            .heart_beat_timeout = options.websocket_options.heart_beat_timeout.value_or(5000),
            .disconnect_on_heart_beat_timeout = options.websocket_options.disconnect_on_heart_beat_timeout.value_or(true)
        },
        .notifications = options.notifications.value_or(true),
        .over_ecdhe = options.over_ecdhe.value_or(true),
        .restorable_session = options.restorable_session.value_or(true),
        .connection_request_timeout = options.connection_request_timeout.value_or(15000),
        .server_agent_validator = options.server_agent_validator,
        .tickets = {
            .ttl_threshold = options.tickets.ttl_threshold.value_or(60 * 1000),
            .min_ticket_ttl = options.tickets.min_ticket_ttl.value_or(5 * 1000),
            .min_tickets_count = options.tickets.min_tickets_count.value_or(10),
            .tickets_count = options.tickets.tickets_count.value_or(50),
            .checker_enabled = options.tickets.checker_enabled.value_or(true),
            .checker_interval = options.tickets.checker_interval.value_or(10000),
            .check_tickets = options.tickets.check_tickets.value_or(true),
            .fetch_tickets_timeout = options.tickets.fetch_tickets_timeout.value_or(10000),
        },
        .app_handler = {
            .timeout_timer_value = options.app_handler.timeout_timer_value.value_or(500),
            .default_timeout = options.app_handler.default_timeout.value_or(40000),
            .default_message_priority = options.app_handler.default_message_priority.value_or(2),
            .max_messages_count = options.app_handler.max_messages_count.value_or(4),
            .max_message_size = options.app_handler.max_message_size.value_or(1024 * 1024)
        }
    };
    if (!RpcUtils::isValidHostname(options.host)) {
        throw InvalidHostException();
    }
    if (res.main_channel == ChannelType::WEBSOCKET && !res.websocket) {
        throw WebsocketCannotBeMainChannelWhenItIsDisabledException();
    }
    return res;
}
