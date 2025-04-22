/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_VALIDATOR_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_VALIDATOR_HPP_

#include <Poco/Dynamic/Var.h>

#include <privmx/utils/Utils.hpp>
#include <string>

#include "privmx/endpoint/core/Events.hpp"
#include "privmx/endpoint/core/Types.hpp"

namespace privmx {
namespace endpoint {
namespace core {

template<typename T>
class StructValidator {
public:
    static void validate(const T& value, const std::string& stack_trace = "") = delete;
    static std::string getReadableType() = delete;
};

template<typename T>
class StructValidator<std::vector<T>> {
public:
    static void validate(const std::vector<T>& value, const std::string& stack_trace = "");
    static std::string getReadableType();
};

template<typename T>
inline void StructValidator<std::vector<T>>::validate(const std::vector<T>& value, const std::string& stack_trace) {
    for (size_t i = 0; i < value.size(); i++) {
        StructValidator<T>::validate(
            value[i], (stack_trace == "" ? stack_trace + "\n" : "") +
                          (StructValidator<std::vector<T>>::getReadableType() + " element nr " + std::to_string(i)));
    }
}

template<typename T>
inline std::string StructValidator<std::vector<T>>::getReadableType() {
    return "std::vector<" + StructValidator<T>::getReadableType() + ">";
}

class Validator {
public:
    static void validateMaxLength(const std::string& value, size_t max_len, const std::string& stack_trace = "");
    static void validateLength(const std::string& value, size_t len, const std::string& stack_trace = "");
    static void validateLengthSize(const std::string& value, size_t min_len, size_t max_len,
                                   const std::string& stack_trace = "");
    static void validateNumberPositive(int64_t value, const std::string& stack_trace = "");
    static void validateNumberPositive(uint64_t value, const std::string& stack_trace = "");
    static void validateNumberPositive(int32_t value, const std::string& stack_trace = "");
    static void validateNumberPositive(uint32_t value, const std::string& stack_trace = "");
    static void validateNumberNegative(int64_t value, const std::string& stack_trace = "");
    static void validateNumberNegative(uint64_t value, const std::string& stack_trace = "");
    static void validateNumberNegative(int32_t value, const std::string& stack_trace = "");
    static void validateNumberNegative(uint32_t value, const std::string& stack_trace = "");
    static void validateNumberNonNegative(int64_t value, const std::string& stack_trace = "");
    static void validateNumberNonNegative(uint64_t value, const std::string& stack_trace = "");
    static void validateNumberNonNegative(int32_t value, const std::string& stack_trace = "");
    static void validateNumberNonNegative(uint32_t value, const std::string& stack_trace = "");
    static void validateNumberNonPositive(int64_t value, const std::string& stack_trace = "");
    static void validateNumberNonPositive(uint64_t value, const std::string& stack_trace = "");
    static void validateNumberNonPositive(int32_t value, const std::string& stack_trace = "");
    static void validateNumberNonPositive(uint32_t value, const std::string& stack_trace = "");

    static void validateBase64(const std::string& value, const std::string& stack_trace = "");
    static void validateBase58(const std::string& value, const std::string& stack_trace = "");
    static void validateSortOrder(const std::string& value, const std::string& stack_trace = "");
    static void validateLastId(const std::string& value, const std::string& stack_trace = "");

    static void validateId(const std::string& value, const std::string& stack_trace = "");
    static void validatePrivKeyWIF(const std::string& value, const std::string& stack_trace = "");
    static void validatePubKeyBase58DER(const std::string& value, const std::string& stack_trace = "");
    static void validateSignature(const std::string& value, const std::string& stack_trace = "");
    static void validateEventType(const Event& value, const std::string& type, const std::string& stack_trace = "");
    template<typename T>
    static void validateClass(const T& value, const std::string& stack_trace = "") {
        StructValidator<T>::validate(value, stack_trace + StructValidator<T>::getReadableType());
    }
};

template<>
class StructValidator<Context> {
public:
    static void validate(const Context& value, const std::string& stack_trace = "");
    static std::string getReadableType() { return "Context"; }
};

template<>
class StructValidator<PagingList<Context>> {
public:
    static void validate(const PagingList<Context>& value, const std::string& stack_trace = "");
    static std::string getReadableType() { return "ContextsList"; }
};

template<>
class StructValidator<UserWithPubKey> {
public:
    static void validate(const UserWithPubKey& value, const std::string& stack_trace = "");
    static std::string getReadableType() { return "UserWithPubKey"; }
};

template<>
class StructValidator<PagingQuery> {
public:
    static void validate(const PagingQuery& value, const std::string& stack_trace = "");
    static std::string getReadableType() { return "PagingQuery"; }
};

template<>
class StructValidator<LibPlatformDisconnectedEvent> {
public:
    static void validate(const LibPlatformDisconnectedEvent& value, const std::string& stack_trace = "");
    static std::string getReadableType() { return "LibPlatformDisconnectedEvent"; }
};

template<>
class StructValidator<VerificationOptions> {
public:
    static void validate(const VerificationOptions& value, const std::string& stack_trace = "");
    static std::string getReadableType() { return "VerificationOptions"; }
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_VALIDATOR_HPP_
