#include <string>

#include "privmx/endpoint/core/Validator.hpp"
#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/utils/Utils.hpp"
#include "privmx/crypto/utils/Base58.hpp"
#include "privmx/crypto/ecc/PrivateKey.hpp"

using namespace std;
using namespace privmx::endpoint::core;

void Validator::validateMaxLength(const string& value, size_t max_len, const string& stack_trace) {
    if(value.length() > max_len) {
        throw InvalidParamsException(stack_trace + " | " + ("Invalid max length, expected max length " + to_string(max_len) + ", received length " + to_string(value.length())));
    }
}

void Validator::validateLength(const string& value, size_t len, const string& stack_trace) {
    if(value.length() != len) {
        throw InvalidParamsException(stack_trace + " | " + ("Invalid length, expected length " + to_string(len) + ", received length " + to_string(value.length())));
    }
}

void Validator::validateLengthSize(const std::string& value, size_t min_len, size_t max_len, const string& stack_trace) {
    if(value.length() < min_len || value.length() > max_len) {
        throw InvalidParamsException(stack_trace + " | " + ("Invalid length, expected length " + to_string(min_len) + "-" + to_string(max_len)  + ", received length " + to_string(value.length())));
    }
}

void Validator::validateId(const std::string& value, const string& stack_trace) {
    validateLengthSize(value, 1,128, stack_trace + " | " + ("Validating string Id"));
}

void Validator::validateNumberPositive(int64_t value, const std::string& stack_trace) {
    if(value <= 0) {
        throw InvalidParamsException(stack_trace + " | " + ("Invalid number, expected positive number, received " + to_string(value)));
    }
}

void Validator::validateNumberPositive( [[maybe_unused]] uint64_t value, [[maybe_unused]] const std::string& stack_trace) {
    if(value <= 0) {
        throw InvalidParamsException(stack_trace + " | " + ("Invalid number, expected positive number, received " + to_string(value)));
    }
}

void Validator::validateNumberPositive(int32_t value, const std::string& stack_trace) {
    if(value <= 0) {
        throw InvalidParamsException(stack_trace + " | " + ("Invalid number, expected positive number, received " + to_string(value)));
    }
}

void Validator::validateNumberPositive([[maybe_unused]] uint32_t value, [[maybe_unused]] const std::string& stack_trace) {
    if(value <= 0) {
        throw InvalidParamsException(stack_trace + " | " + ("Invalid number, expected positive number, received " + to_string(value)));
    }
}

void Validator::validateBase64(const string& value, const string& stack_trace) {
    if(!privmx::utils::Base64::is(value)) {
        throw InvalidParamsException(stack_trace + " | " + ("Invalid Base64"));
    }
}

void Validator::validateNumberNegative(int64_t value, const std::string& stack_trace) {
    if(value >= 0) {
        throw InvalidParamsException(stack_trace + " | " + ("Invalid number, expected negative number, received " + to_string(value)));
    }
}

void Validator::validateNumberNegative(uint64_t value, const std::string& stack_trace) {
    throw InvalidParamsException(stack_trace + " | " + ("Invalid number, expected negative number, received " + to_string(value)));
}

void Validator::validateNumberNegative(int32_t value, const std::string& stack_trace) {
    if(value >= 0) {
        throw InvalidParamsException(stack_trace + " | " + ("Invalid number, expected negative number, received " + to_string(value)));
    }
}

void Validator::validateNumberNegative(uint32_t value, const std::string& stack_trace) {
    throw InvalidParamsException(stack_trace + " | " + ("Invalid number, expected negative number, received " + to_string(value)));
}

void Validator::validateNumberNonNegative(int64_t value, const std::string& stack_trace) {
    if(value < 0) {
        throw InvalidParamsException(stack_trace + " | " + ("Invalid number, expected negative number, received " + to_string(value)));
    }
}

void Validator::validateNumberNonNegative([[maybe_unused]] uint64_t value, [[maybe_unused]] const std::string& stack_trace) {}

void Validator::validateNumberNonNegative(int32_t value, const std::string& stack_trace) {
    if(value < 0) {
        throw InvalidParamsException(stack_trace + " | " + ("Invalid number, expected no negative number, received " + to_string(value)));
    }
}

void Validator::validateNumberNonNegative([[maybe_unused]] uint32_t value, [[maybe_unused]] const std::string& stack_trace) {}

void Validator::validateNumberNonPositive(int64_t value, const std::string& stack_trace) {
    if(value > 0) {
        throw InvalidParamsException(stack_trace + " | " + ("Invalid number, expected no positive number, received " + to_string(value)));
    }
}

void Validator::validateNumberNonPositive(uint64_t value, const std::string& stack_trace) {
    if(value > 0) {
        throw InvalidParamsException(stack_trace + " | " + ("Invalid number, expected no positive number, received " + to_string(value)));
    }
}

void Validator::validateNumberNonPositive(int32_t value, const std::string& stack_trace) {
    if(value > 0) {
        throw InvalidParamsException(stack_trace + " | " + ("Invalid number, expected no positive number, received " + to_string(value)));
    }
}

void Validator::validateNumberNonPositive(uint32_t value, const std::string& stack_trace) {
    if(value > 0) {
        throw InvalidParamsException(stack_trace + " | " + ("Invalid number, expected no positive number, received " + to_string(value)));
    }
}

void Validator::validateBase58(const string& value, const string& stack_trace) {
    if(!privmx::utils::Base58::is(value)) {
        throw InvalidParamsException(stack_trace + " | " + ("Invalid Base64"));
    }
}

void Validator::validateSortOrder(const std::string& value, const std::string& stack_trace) {
    if(value.empty()) {
        throw InvalidParamsException(stack_trace + " | " + ("Invalid sortOrder, is empty"));
    }
    if(value != "asc" && value != "desc") {
        throw InvalidParamsException(stack_trace + " | " + ("Invalid sortOrder, isn't 'asc' or 'desc', received '" + value + "'"));
    }
}

void Validator::validateLastId(const std::string& value, const std::string& stack_trace) {
    if(value.empty()) {
        throw InvalidParamsException(stack_trace + " | " + ("Invalid lastId, is empty"));
    }
    return validateId(value, stack_trace);
}

void Validator::validatePrivKeyWIF(const string& value, const string& stack_trace) {
    Validator::validateBase58(value, stack_trace);
    try {
        privmx::crypto::PrivateKey::fromWIF(value);
    } catch (...) {
        throw InvalidParamsException(stack_trace + " | " + ("Invalid PrivKeyWIF"));
    }
    
}

void Validator::validatePubKeyBase58DER(const string& value, const string& stack_trace) {
    Validator::validateBase58(value, stack_trace);
}

void Validator::validateEventType(const Event& value, const std::string& type, const std::string& stack_trace) {
    if(value.type != type) {
        throw InvalidParamsException(stack_trace + " | " + ("Invalid Event type, expected '"+ type +"', received '" + value.type + "'"));
    }
}


void StructValidator<Context>::validate(const Context& value, const std::string& stack_trace) {
    Validator::validateId(value.userId, stack_trace + ".storeId");
    Validator::validateId(value.contextId, stack_trace + ".contextId");
}

void StructValidator<PagingList<Context>>::validate(const PagingList<Context>& value, const std::string& stack_trace) {
    Validator::validateNumberPositive(value.totalAvailable, stack_trace + ".contextsTotal");
    StructValidator<std::vector<Context>>::validate(value.readItems, stack_trace + ".contexts");
    
}

void StructValidator<UserWithPubKey>::validate(const UserWithPubKey& value, const std::string& stack_trace) {
    Validator::validateId(value.userId, stack_trace + ".storeId");
    Validator::validatePubKeyBase58DER(value.pubKey, stack_trace + ".pubKey");
}

void StructValidator<PagingQuery>::validate(const PagingQuery& value, const std::string& stack_trace) {
    Validator::validateSortOrder(value.sortOrder, stack_trace + ".sortOrder");
    if (value.lastId.has_value()) {
        Validator::validateLastId(value.lastId.value(), stack_trace + ".lastId");
    }
}

void StructValidator<LibPlatformDisconnectedEvent>::validate(const LibPlatformDisconnectedEvent& value, const std::string& stack_trace) {
    Validator::validateEventType(value, "libPlatformDisconnected", stack_trace + ".type");
}

