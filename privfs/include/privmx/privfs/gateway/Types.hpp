/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_PRIVFS_GATEWAY_TYPES_HPP_
#define _PRIVMXLIB_PRIVFS_GATEWAY_TYPES_HPP_

#include <privmx/utils/TypedObject.hpp>
#include <privmx/utils/TypesMacros.hpp>
#include <privmx/rpc/Types.hpp>

namespace privmx {
namespace privfs {
namespace types {

class PresenceEntry : public utils::TypedObject
{
public:
    SERVER_TYPE_CONSTRUCTOR(PresenceEntry)
    void initialize() override {
        initializeObject({"status", "timestamp"});        
    }
    STRING_FIELD(status)
    STRING_FIELD(timestamp)
};

class PresenceSingleRes : public utils::TypedObject
{
public:
    SERVER_TYPE_CONSTRUCTOR(PresenceSingleRes)
    void initialize() override {
        initializeObject({"pkiRevision", "signature"});
        INIT_OBJECT(entry, PresenceEntry)       
    }
    STRING_FIELD(pkiRevision)
    STRING_FIELD(signature)
    OBJECT_FIELD(entry, PresenceEntry) 
};

class RawPresenceInfo : public utils::TypedObject
{
public:
    SERVER_TYPE_CONSTRUCTOR(RawPresenceInfo)
    void initialize() override {
        initializeObject({"signature", "acl"});
        INIT_OBJECT(entry, PresenceEntry)       
    }
    OBJECT_FIELD(entry, PresenceEntry)
    STRING_FIELD(signature)
    STRING_FIELD(acl)
};

class NotificationsEntry : public utils::TypedObject
{
public:
    SERVER_TYPE_CONSTRUCTOR(NotificationsEntry)
    void initialize() override {
        initializeObject({"enabled", "email"});
        INIT_LIST(tags, std::string)
        INIT_LIST(mutedSinks, std::string)
        INIT_LIST(ignoredDomains, std::string)
    }
    BOOL_FIELD(enabled)
    STRING_FIELD(email)
    LIST_FIELD(tags, std::string)
    LIST_FIELD(mutedSinks, std::string)
    LIST_FIELD(ignoredDomains, std::string)
};

class RawMyData : public utils::TypedObject
{
public:
    SERVER_TYPE_CONSTRUCTOR(RawMyData)
    void initialize() override {
        initializeObject({"username", "isAdmin", "keystore", "keystoreMsg", "contactFormEnabled", "secureFormsEnabled", "generatedPassword", "login", "type"});
        INIT_LIST(plugins, std::string)
        INIT_OBJECT(presence, RawPresenceInfo)
        INIT_OBJECT(notificationsEntry, NotificationsEntry)
        INIT_LIST(rights, std::string)
    }
    STRING_FIELD(username)
    BOOL_FIELD(isAdmin)
    LIST_FIELD(plugins, std::string)
    OBJECT_FIELD(presence, RawPresenceInfo)
    OBJECT_FIELD(notificationsEntry, NotificationsEntry)
    BINARYSTRING_FIELD(keystore)
    BINARYSTRING_FIELD(keystoreMsg)
    BOOL_FIELD(contactFormEnabled)
    BOOL_FIELD(secureFormsEnabled)
    BOOL_FIELD(generatedPassword)
    STRING_FIELD(login)
    STRING_FIELD(utypesername)
    LIST_FIELD(rights, std::string)
};

struct InitParameters
{
    rpc::ConnectionOptions options;
    rpc::GatewayProperties::Ptr gateway_properties;
    std::optional<rpc::AdditionalLoginStepCallback> additional_login_step_callback;
    
    Poco::Dynamic::Var serializeToVar(){
        Poco::Dynamic::Var package = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
        auto object= package.extract<Poco::JSON::Object::Ptr>();
        
        object->set("options",this->options.serializeToVar());
        object->set("gatewayProperties",this->gateway_properties);
        //TODO callback
        // if(this->additional_login_step_callback.has_value()){ 
        //     object->set("additionalLoginStepCallback",this->additional_login_step_callback);
        // }
        return package;
    }
};

struct InitParametersFull
{
    rpc::ConnectionOptionsFull options;
    rpc::GatewayProperties::Ptr gateway_properties;
    std::optional<rpc::AdditionalLoginStepCallback> additional_login_step_callback;
    
    Poco::Dynamic::Var serializeToVar(){
        Poco::Dynamic::Var package = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
        auto object= package.extract<Poco::JSON::Object::Ptr>();

        object->set("options",this->options.serializeToVar());
        object->set("gatewayProperties",this->gateway_properties);
        //TODO callback
        // if(this->additional_login_step_callback.has_value()){
        //     object->set("additionalLoginStepCallback",this->additional_login_step_callback);
        // }
        return package;
    }
};

} // types
} // privfs
} // privmx

#endif // _PRIVMXLIB_PRIVFS_GATEWAY_TYPES_HPP_
