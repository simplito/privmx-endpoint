#include "privmx/endpoint/group/VarDeserializer.hpp"

#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>

#include <privmx/endpoint/core/CoreException.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

template<>
group::GroupMemberToAdd VarDeserializer::deserialize<group::GroupMemberToAdd>(
    const Poco::Dynamic::Var& val,
    const std::string& name
) {
    core::TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    return {
        .user = deserialize<core::UserWithPubKey>(obj->get("user"), name + ".user"),
        .role = deserialize<std::string>(obj->get("role"), name + ".role")
    };
}

template<>
group::GroupRoleChange VarDeserializer::deserialize<group::GroupRoleChange>(
    const Poco::Dynamic::Var& val,
    const std::string& name
) {
    core::TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    return {
        .userId = deserialize<std::string>(obj->get("userId"), name + ".userId"),
        .role = deserialize<std::string>(obj->get("role"), name + ".role")
    };
}

template<>
group::GroupRulesUpdate VarDeserializer::deserialize<group::GroupRulesUpdate>(
    const Poco::Dynamic::Var& val,
    const std::string& name
) {
    core::TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    return {
        .addMembers = deserializeOptional<std::string>(obj->get("addMembers"), name + ".addMembers"),
        .removeMembers = deserializeOptional<std::string>(obj->get("removeMembers"), name + ".removeMembers"),
        .replaceMemberKeys = deserializeOptional<std::string>(
            obj->get("replaceMemberKeys"), name + ".replaceMemberKeys"
        ),
        .changeRoles = deserializeOptional<std::string>(obj->get("changeRoles"), name + ".changeRoles"),
        .changeRules = deserializeOptional<std::string>(obj->get("changeRules"), name + ".changeRules"),
        .changeVisibility = deserializeOptional<std::string>(obj->get("changeVisibility"), name + ".changeVisibility"),
        .trimHistory = deserializeOptional<std::string>(obj->get("trimHistory"), name + ".trimHistory"),
        .editPublicMeta = deserializeOptional<std::string>(obj->get("editPublicMeta"), name + ".editPublicMeta"),
        .editPrivateMeta = deserializeOptional<std::string>(obj->get("editPrivateMeta"), name + ".editPrivateMeta")
    };
}

template<>
group::EventType VarDeserializer::deserialize<group::EventType>(
    const Poco::Dynamic::Var& val,
    const std::string& name
) {

    switch (val.convert<int64_t>()) {
    case group::EventType::GROUP_CREATE:
        return group::EventType::GROUP_CREATE;
    case group::EventType::GROUP_UPDATE:
        return group::EventType::GROUP_UPDATE;
    case group::EventType::GROUP_DELETE:
        return group::EventType::GROUP_DELETE;
    case group::EventType::SPACE_CREATE:
        return group::EventType::SPACE_CREATE;
    case group::EventType::SPACE_UPDATE:
        return group::EventType::SPACE_UPDATE;
    case group::EventType::SPACE_DELETE:
        return group::EventType::SPACE_DELETE;
    }
    throw InvalidParamsException(
        name + " | " + ("Unknown group::EventType value, received " + std::to_string(val.convert<int64_t>()))
    );
}

template<>
group::EventSelectorType VarDeserializer::deserialize<group::EventSelectorType>(
    const Poco::Dynamic::Var& val,
    const std::string& name
) {

    switch (val.convert<int64_t>()) {
    case group::EventSelectorType::CONTEXT_ID:
        return group::EventSelectorType::CONTEXT_ID;
    case group::EventSelectorType::GROUP_ID:
        return group::EventSelectorType::GROUP_ID;
    case group::EventSelectorType::SPACE_ID:
        return group::EventSelectorType::SPACE_ID;
    }
    throw InvalidParamsException(
        name + " | " + ("Unknown group::EventSelectorType value, received " + std::to_string(val.convert<int64_t>()))
    );
}

template<>
group::PathSegment VarDeserializer::deserialize<group::PathSegment>(
    const Poco::Dynamic::Var& val,
    const std::string& name
) {
    core::TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    return {
        .isId = deserialize<bool>(obj->get("isId"), name + ".isId"),
        .value = deserialize<core::Buffer>(obj->get("value"), name + ".value")
    };
}

template<>
group::DecryptOptions VarDeserializer::deserialize<group::DecryptOptions>(
    const Poco::Dynamic::Var& val,
    const std::string& name
) {
    core::TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    // Absent fields mean "not set": the call itself refuses options that name no author.
    return {
        .expectedAuthor = deserializeOptional<std::string>(obj->get("expectedAuthor"), name + ".expectedAuthor")
                              .value_or(std::string()),
        .anyAuthor = deserializeOptional<bool>(obj->get("anyAuthor"), name + ".anyAuthor").value_or(false),
        .currentEpochOnly = deserializeOptional<bool>(obj->get("currentEpochOnly"), name + ".currentEpochOnly")
                                .value_or(false)
    };
}

template<>
group::SpaceRecipient VarDeserializer::deserialize<group::SpaceRecipient>(
    const Poco::Dynamic::Var& val,
    const std::string& name
) {
    core::TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    return {
        .groupId = deserializeOptional<std::string>(obj->get("groupId"), name + ".groupId").value_or(std::string()),
        .user = deserializeOptional<core::UserWithPubKey>(obj->get("user"), name + ".user"),
        .role = deserialize<std::string>(obj->get("role"), name + ".role")
    };
}

template<>
group::SpaceRecipientRef VarDeserializer::deserialize<group::SpaceRecipientRef>(
    const Poco::Dynamic::Var& val,
    const std::string& name
) {
    core::TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    return {
        .groupId = deserializeOptional<std::string>(obj->get("groupId"), name + ".groupId").value_or(std::string()),
        .userId = deserializeOptional<std::string>(obj->get("userId"), name + ".userId").value_or(std::string())
    };
}

template<>
group::EnvelopeRecipient VarDeserializer::deserialize<group::EnvelopeRecipient>(
    const Poco::Dynamic::Var& val,
    const std::string& name
) {
    core::TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    return {
        .groupId = deserializeOptional<std::string>(obj->get("groupId"), name + ".groupId").value_or(std::string()),
        .user = deserializeOptional<core::UserWithPubKey>(obj->get("user"), name + ".user")
    };
}

template<>
group::EncryptOptions VarDeserializer::deserialize<group::EncryptOptions>(
    const Poco::Dynamic::Var& val,
    const std::string& name
) {
    if (val.isEmpty()) {
        return {};
    }
    core::TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    return {
        .alsoFor = deserializeOptionalVector<group::EnvelopeRecipient>(obj->get("alsoFor"), name + ".alsoFor")
                       .value_or(std::vector<group::EnvelopeRecipient>{})
    };
}

template<>
group::DecryptItem VarDeserializer::deserialize<group::DecryptItem>(
    const Poco::Dynamic::Var& val,
    const std::string& name
) {
    core::TypeValidator::validateObject(val, name);
    Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();
    return {
        .envelope = deserialize<core::Buffer>(obj->get("envelope"), name + ".envelope"),
        .location = deserializeVector<group::PathSegment>(obj->get("location"), name + ".location"),
        .options = deserialize<group::DecryptOptions>(obj->get("options"), name + ".options")
    };
}
