#ifndef _PRIVMXLIB_RPC_TYPES_HPP_
#define _PRIVMXLIB_RPC_TYPES_HPP_

#include <optional>
#include <functional>
#include <Poco/JSON/Object.h>
#include <Poco/SharedPtr.h>

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/utils/TypedObject.hpp>
#include <privmx/utils/TypesMacros.hpp>
#include <privmx/rpc/channel/WebSocketChannel.hpp>

namespace privmx {
namespace rpc {

using GatewayProperties = Poco::JSON::Object;

class SecondFactorService
{
public:
    using Ptr = Poco::SharedPtr<SecondFactorService>;

    virtual ~SecondFactorService() = default;
    virtual std::string getHost() = 0;
    virtual void confirm(Poco::JSON::Object::Ptr model) = 0;
    virtual void resendCode() = 0;
    virtual void reject(const std::string& e) = 0;
};

using AdditionalLoginStepCallback = std::function<void(Poco::Dynamic::Var, SecondFactorService::Ptr)>;

struct ServerConfig {
    size_t requestChunkSize;
};

struct ConnectionInfo
{
    using Ptr = Poco::SharedPtr<ConnectionInfo>;
    
    ConnectionInfo(const std::string& type) : type(type) {}
    virtual ~ConnectionInfo() = default;
    
    virtual Poco::Dynamic::Var serializeToVar(){
        Poco::Dynamic::Var package = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
        auto object= package.extract<Poco::JSON::Object::Ptr>();
        object->set("type",this->type);
        return package;
    }

    std::string type;
    ServerConfig serverConfig;
};

struct EcdheConnectionInfo : public ConnectionInfo
{
    using Ptr = Poco::SharedPtr<EcdheConnectionInfo>;

    EcdheConnectionInfo() : ConnectionInfo("ecdhe") {}
    virtual ~EcdheConnectionInfo() = default;

    Poco::Dynamic::Var serializeToVar() override {
        Poco::Dynamic::Var package = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
        auto object= package.extract<Poco::JSON::Object::Ptr>();
        object->set("type",this->type);
        object->set("key",key.toBase58DER());
        return package;
    }
        
    crypto::PublicKey key;
};

struct EcdhexConnectionInfo : public ConnectionInfo
{
    using Ptr = Poco::SharedPtr<EcdhexConnectionInfo>;

    EcdhexConnectionInfo() : ConnectionInfo("ecdhex") {}
    virtual ~EcdhexConnectionInfo() = default;

    Poco::Dynamic::Var serializeToVar() override {
        Poco::Dynamic::Var package = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
        auto object= package.extract<Poco::JSON::Object::Ptr>();
        object->set("type",this->type);
        object->set("key",key.toBase58DER());
        return package;
    }
        
    crypto::PublicKey key;
    std::string host;
};

struct ConnectionInfoWithSession : public ConnectionInfo
{
    using Ptr = Poco::SharedPtr<ConnectionInfoWithSession>;

    ConnectionInfoWithSession(const std::string& type) : ConnectionInfo(type) {}
    virtual ~ConnectionInfoWithSession() = default;

    Poco::Dynamic::Var serializeToVar() override {
        Poco::Dynamic::Var package = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
        auto object= package.extract<Poco::JSON::Object::Ptr>();
        object->set("type",this->type);
        object->set("sessionId",this->session_id);
        if(session_key.has_value()){
            object->set("sessionKey",this->session_key.value().toWIF());
        }
        object->set("username",this->username);
        object->set("properties",this->properties);
        return package;
    }

    std::string session_id;
    std::optional<crypto::PrivateKey> session_key;
    GatewayProperties::Ptr properties;
    std::string username;
};

struct SrpConnectionInfo : public ConnectionInfoWithSession
{
    using Ptr = Poco::SharedPtr<SrpConnectionInfo>;

    SrpConnectionInfo() : ConnectionInfoWithSession("srp") {}
    virtual ~SrpConnectionInfo() = default;

    Poco::Dynamic::Var serializeToVar() override {
        Poco::Dynamic::Var package = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
        auto object= package.extract<Poco::JSON::Object::Ptr>();
        object->set("type",this->type);
        object->set("sessionId",this->session_id);
        if(session_key.has_value()){
            object->set("sessionKey",this->session_key.value().toWIF());
        }
        object->set("username",this->username);
        object->set("mixed",Pson::BinaryString(this->mixed));
        object->set("properties",this->properties);
        return package;
    }

    std::string mixed;
};

struct KeyConnectionInfo : public ConnectionInfoWithSession
{
    using Ptr = Poco::SharedPtr<KeyConnectionInfo>;

    KeyConnectionInfo() : ConnectionInfoWithSession("key") {}
    virtual ~KeyConnectionInfo() = default;

    Poco::Dynamic::Var serializeToVar()     override {
        Poco::Dynamic::Var package = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
        auto object= package.extract<Poco::JSON::Object::Ptr>();
        object->set("type",this->type);
        object->set("sessionId",this->session_id);
        if(session_key.has_value()){
            object->set("sessionKey",this->session_key.value().toWIF());
        }
        object->set("username",this->username);
        object->set("key",this->key.toBase58DER());
        object->set("properties",this->properties);
        return package;
    }
    
    crypto::PublicKey key;
};

struct SessionConnectionInfo : public ConnectionInfoWithSession
{
    using Ptr = Poco::SharedPtr<SessionConnectionInfo>;

    SessionConnectionInfo() : ConnectionInfoWithSession("session") {}
    virtual ~SessionConnectionInfo() = default;
};

struct HeartBeatEvent
{
    const std::string type = "heartBeat";
    int latency;
    WebSocketChannel::Ptr websocket;
};

struct WebSocketOptions
{
    std::optional<int> connect_timeout;
    std::optional<int> ping_timeout;
    std::optional<std::function<void(const HeartBeatEvent&)>> on_heart_beat_callback;
    std::optional<int> heart_beat_timeout;
    std::optional<bool> disconnect_on_heart_beat_timeout;

    Poco::Dynamic::Var serializeToVar(){
        Poco::Dynamic::Var package = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
        auto object= package.extract<Poco::JSON::Object::Ptr>();
        if(connect_timeout.has_value()){
            object->set("connectTimeout",this->connect_timeout.value());
        }
        if(ping_timeout.has_value()){
            object->set("pingTimeout",this->ping_timeout.value());
        }
        //TODO callback
        // if(on_heart_beat_callback.has_value()){
        //     object->set("onHeartBeatCallback",this->on_heart_beat_callback.value());
        // }
        if(heart_beat_timeout.has_value()){
            object->set("heartBeatTimeout",this->heart_beat_timeout.value());
        }
        if(disconnect_on_heart_beat_timeout.has_value()){
            object->set("disconnectOnHeartBeatTimeout",this->disconnect_on_heart_beat_timeout.value());
        }
        return package;
    }
};

struct TicketConfig
{
    std::optional<int> ttl_threshold;
    std::optional<int> min_ticket_ttl;
    std::optional<int> min_tickets_count;
    std::optional<int> tickets_count;
    std::optional<bool> checker_enabled;
    std::optional<int> checker_interval;
    std::optional<bool> check_tickets;
    std::optional<int> fetch_tickets_timeout;
    
    Poco::Dynamic::Var serializeToVar(){
        Poco::Dynamic::Var package = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
        auto object= package.extract<Poco::JSON::Object::Ptr>();
        if(ttl_threshold.has_value()){
            object->set("ttlThreshold",this->ttl_threshold.value());
        }
        if(min_ticket_ttl.has_value()){
            object->set("minTicketTtl",this->min_ticket_ttl.value());
        }
        if(min_tickets_count.has_value()){
            object->set("minTicketsCount",this->min_tickets_count.value());
        }
        if(tickets_count.has_value()){
            object->set("ticketsCount",this->tickets_count.value());
        }
        if(checker_enabled.has_value()){
            object->set("checkerEnabled",this->checker_enabled.value());
        }
        if(checker_interval.has_value()){
            object->set("checkerInterval",this->checker_interval.value());
        }
        if(check_tickets.has_value()){
            object->set("checkTickets",this->check_tickets.value());
        }
        if(fetch_tickets_timeout.has_value()){
            object->set("fetchTicketsTimeout",this->fetch_tickets_timeout.value());
        }
        return package;
    }
};

struct AppHandlerOptions 
{
    std::optional<int> timeout_timer_value;
    std::optional<int> default_timeout;
    std::optional<int> default_message_priority;
    std::optional<int> max_messages_count;
    std::optional<int> max_message_size;
    
    Poco::Dynamic::Var serializeToVar(){
        Poco::Dynamic::Var package = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
        auto object= package.extract<Poco::JSON::Object::Ptr>();
        if(timeout_timer_value.has_value()){
            object->set("timeoutTimerValue",this->timeout_timer_value.value());
        }
        if(default_timeout.has_value()){
            object->set("defaultTimeout",this->default_timeout.value());
        }
        if(default_message_priority.has_value()){
            object->set("defaultMessagePriority",this->default_message_priority.value());
        }
        if(max_messages_count.has_value()){
            object->set("maxMessagesCount",this->max_messages_count.value());
        }
        if(max_message_size.has_value()){
            object->set("maxMessageSize",this->max_message_size.value());
        }
        return package;
    }
};

enum class ChannelType
{
    AJAX = 1,
    WEBSOCKET = 2
};

struct ConnectionOptions
{
    std::string url;
    std::string host;
    std::optional<std::string> agent;
    std::optional<ChannelType> main_channel;
    std::optional<bool> websocket;
    WebSocketOptions websocket_options;
    std::optional<bool> notifications;
    std::optional<bool> over_ecdhe;
    std::optional<bool> restorable_session;
    std::optional<int> connection_request_timeout;
    std::function<void(const std::string&)> server_agent_validator; 
    TicketConfig tickets;
    AppHandlerOptions app_handler;

    Poco::Dynamic::Var serializeToVar(){
        Poco::Dynamic::Var package = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
        auto object= package.extract<Poco::JSON::Object::Ptr>();
        object->set("url",this->url);
        object->set("host",this->host);
        object->set("websocketOptions",this->websocket_options.serializeToVar());
        object->set("tickets",this->tickets.serializeToVar());
        object->set("appHandler",this->app_handler.serializeToVar());
        //TODO callback
        //object->set("serverAgentValidator",this->server_agent_validator);
        if(agent.has_value()){
            object->set("agent",this->agent.value());
        }
        if(main_channel.has_value()){
            object->set("mainChannel",(this->main_channel.value() == ChannelType::AJAX) ? "ajax" : "websocket"); 
        }
        if(websocket.has_value()){
            object->set("websocket",this->websocket.value());
        }
        if(notifications.has_value()){
            object->set("notifications",this->notifications.value());
        }
        if(over_ecdhe.has_value()){
            object->set("overEcdhe",this->over_ecdhe.value());
        }
        if(restorable_session.has_value()){
            object->set("restorableSession",this->restorable_session.value());
        }
        if(connection_request_timeout.has_value()){
            object->set("connectionRequestTimeout",this->connection_request_timeout.value());
        }
        return package;
    }
    
};

struct WebSocketOptionsFull
{
    int connect_timeout;
    int ping_timeout;
    std::function<void(const HeartBeatEvent&)> on_heart_beat_callback;
    int heart_beat_timeout;
    bool disconnect_on_heart_beat_timeout;

    WebSocketOptions asOpt() const {
        return {
            .connect_timeout = connect_timeout,
            .ping_timeout = ping_timeout,
            .on_heart_beat_callback = on_heart_beat_callback,
            .heart_beat_timeout = heart_beat_timeout,
            .disconnect_on_heart_beat_timeout = disconnect_on_heart_beat_timeout
        };
    }
    
    Poco::Dynamic::Var serializeToVar(){
        return this->asOpt().serializeToVar();    
    }
};

struct TicketConfigFull
{
    int ttl_threshold;
    int min_ticket_ttl;
    int min_tickets_count;
    int tickets_count;
    bool checker_enabled;
    int checker_interval;
    bool check_tickets;
    int fetch_tickets_timeout;

    TicketConfig asOpt() const {
        return {
            .ttl_threshold = ttl_threshold,
            .min_ticket_ttl = min_ticket_ttl,
            .min_tickets_count = min_tickets_count,
            .tickets_count = tickets_count,
            .checker_enabled = checker_enabled,
            .checker_interval = checker_interval,
            .check_tickets = check_tickets,
            .fetch_tickets_timeout = fetch_tickets_timeout
        };
    }
    
    Poco::Dynamic::Var serializeToVar(){
        return this->asOpt().serializeToVar();    
    }
};

struct AppHandlerOptionsFull
{
    int timeout_timer_value;
    int default_timeout;
    int default_message_priority;
    int max_messages_count;
    int max_message_size;

    AppHandlerOptions asOpt() const {
        return {
            .timeout_timer_value = timeout_timer_value,
            .default_timeout = default_timeout,
            .default_message_priority = default_message_priority,
            .max_messages_count = max_messages_count,
            .max_message_size = max_message_size
        };
    }
    
    Poco::Dynamic::Var serializeToVar(){
        return this->asOpt().serializeToVar();    
    }
};

struct ConnectionOptionsFull
{
    std::string url;
    std::string host;
    std::string agent;
    ChannelType main_channel;
    bool websocket;
    WebSocketOptionsFull websocket_options;
    bool notifications;
    bool over_ecdhe;
    bool restorable_session;
    int connection_request_timeout;
    std::function<void(const std::string&)> server_agent_validator;
    TicketConfigFull tickets;
    AppHandlerOptionsFull app_handler;

    ConnectionOptions asOpt() const {
        return {
            .url = url,
            .host = host,
            .agent = agent,
            .main_channel = main_channel,
            .websocket = websocket,
            .websocket_options = websocket_options.asOpt(),
            .notifications = notifications,
            .over_ecdhe = over_ecdhe,
            .restorable_session = restorable_session,
            .connection_request_timeout = connection_request_timeout,
            .server_agent_validator = server_agent_validator,
            .tickets = tickets.asOpt(),
            .app_handler = app_handler.asOpt()
        };
    }

    Poco::Dynamic::Var serializeToVar(){
        return this->asOpt().serializeToVar();    
    }
};

struct EcdheOptions
{
    std::optional<crypto::PrivateKey> key;
    Poco::Dynamic::Var serializeToVar(){
        Poco::Dynamic::Var package = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
        auto object= package.extract<Poco::JSON::Object::Ptr>();
        if(this->key.has_value()){
            object->set("key",key.value().toWIF());
        }
        return package;
    }
};

struct EcdhexOptions
{
    Poco::Dynamic::Var serializeToVar(){
        Poco::Dynamic::Var package = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
        auto object= package.extract<Poco::JSON::Object::Ptr>();
        object->set("key", key.toWIF());
        if (solution.has_value()) {
            object->set("solution", solution.value());
        }
        object->set("solution", std::nullopt);
        return package;
    }

    crypto::PrivateKey key;
    std::optional<std::string> solution;
};

struct SrpOptions
{
    std::string username;
    std::string password;
    GatewayProperties::Ptr properties;
    std::optional<AdditionalLoginStepCallback> on_additional_login_step;
    
    Poco::Dynamic::Var serializeToVar(){
        Poco::Dynamic::Var package = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
        auto object= package.extract<Poco::JSON::Object::Ptr>();
        
        object->set("username",this->username);
        object->set("password",this->password);
        object->set("properties",this->properties);
        //TODO callback
        // if(this->on_additional_login_step.has_value()){
        //     object->set("onAditionalLoginStep",this->on_additional_login_step);
        // }
        return package;
    }
};

struct KeyOptions
{
    crypto::PrivateKey key;
    GatewayProperties::Ptr properties;
    std::optional<AdditionalLoginStepCallback> on_additional_login_step;
    
    Poco::Dynamic::Var serializeToVar(){
        Poco::Dynamic::Var package = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
        auto object= package.extract<Poco::JSON::Object::Ptr>();
        
        object->set("key",this->key.toWIF());
        object->set("properties",this->properties);
        //TODO callback
        // if(this->on_additional_login_step.has_value()){
        //     object->set("onAditionalLoginStep",this->on_additional_login_step);
        // }
        return package;
    }
};

struct SessionRestoreOptions
{
    std::string session_id;
    crypto::PrivateKey session_key;

    Poco::Dynamic::Var serializeToVar(){
        Poco::Dynamic::Var package = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
        auto object= package.extract<Poco::JSON::Object::Ptr>();
        
        object->set("sessionId",this->session_id);
        object->set("sessionKey",this->session_key.toWIF());
        return package;
    }
};


struct SessionRestoreOptionsEx
{
    std::string session_id;
    crypto::PrivateKey session_key;
    std::string username;
    GatewayProperties::Ptr properties;

    Poco::Dynamic::Var serializeToVar(){
        Poco::Dynamic::Var package = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
        auto object= package.extract<Poco::JSON::Object::Ptr>();
        
        object->set("sessionId",this->session_id);
        object->set("sessionKey",this->session_key.toWIF());
        object->set("username",this->username);
        object->set("properties",this->properties);
        return package;
    }
};

struct MessageSendOptionsEx
{
    std::optional<ChannelType> channel_type = std::nullopt;
    std::optional<int> priority = std::nullopt;
    std::optional<int> timeout = std::nullopt;
    std::optional<bool> send_alone = std::nullopt;
    
    Poco::Dynamic::Var serializeToVar(){
        Poco::Dynamic::Var package = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
        auto object= package.extract<Poco::JSON::Object::Ptr>();
        if(channel_type.has_value()){
            object->set("channelType",this->channel_type.value());
        }
        if(priority.has_value()){
            object->set("priority",this->priority.value());
        }
        if(timeout.has_value()){
            object->set("timeout",this->timeout.value());
        }
        if(send_alone.has_value()){
            object->set("sendAlone",this->send_alone.value());
        }
        return package;
    }

};

struct SrpHandshakeResult
{
    std::string session_id;
    std::optional<crypto::PrivateKey> session_key;
    std::string mixed;
    Poco::JSON::Object::Ptr additional_login_step;
    
    Poco::Dynamic::Var serializeToVar(){
        Poco::Dynamic::Var package = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
        auto object= package.extract<Poco::JSON::Object::Ptr>();
        object->set("sessionId",this->session_id);
        object->set("mixed",Pson::BinaryString(this->mixed));
        object->set("additionalLoginStep",this->additional_login_step);
        if(session_key.has_value()){
            object->set("sessionKey",this->session_key.value().toWIF());
        }
        return package;
    }  
};

struct KeyHandshakeResult
{
    std::string username;
    std::string session_id;
    std::optional<crypto::PrivateKey> session_key;
    Poco::JSON::Object::Ptr additional_login_step;
    
    Poco::Dynamic::Var serializeToVar(){
        Poco::Dynamic::Var package = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
        auto object= package.extract<Poco::JSON::Object::Ptr>();
        object->set("sessionId",this->session_id);
        object->set("username",this->username);
        object->set("additionalLoginStep",this->additional_login_step);
        if(session_key.has_value()){
            object->set("sessionKey",this->session_key.value().toWIF());
        }
        return package;
    }  
};

} // rpc
} // privmx

#endif // _PRIVMXLIB_RPC_TYPES_HPP_
