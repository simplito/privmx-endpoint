/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_UTILS_JSON_HELPER_HPP_
#define _PRIVMXLIB_UTILS_JSON_HELPER_HPP_

#include <type_traits>
#include <iostream>
#include <string>
#include <map>
#include <unordered_map>
#include <optional>
#include <vector>
#include <Pson/BinaryString.hpp>
#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>
#include <privmx/utils/PrivmxExtExceptions.hpp>
#include <privmx/utils/Logger.hpp>

namespace privmx {
namespace utils {


template<typename T>
struct is_vector : std::false_type {};
template<typename T, typename Alloc>
struct is_vector<std::vector<T, Alloc>> : std::true_type {};

template<typename T>
struct is_unordered_map : std::false_type {};
template<typename K, typename V, typename Comp, typename Alloc>
struct is_unordered_map<std::unordered_map<K, V, Comp, Alloc>> : std::true_type {};

template<typename T>
struct is_map : std::false_type {};
template<typename K, typename V, typename Comp, typename Alloc>
struct is_map<std::map<K, V, Comp, Alloc>> : std::true_type {};

template<typename T>
struct is_optional : std::false_type {};
template<typename T>
struct is_optional<std::optional<T>> : std::true_type {};

template<typename T>
class optional_null : public std::optional<T> {
public:
    optional_null() : std::optional<T>() {}
    optional_null(const T& value) : std::optional<T>(value) {}
    optional_null(std::nullopt_t) : std::optional<T>(std::nullopt) {}
    optional_null(const optional_null&) = default;
    optional_null(optional_null&&) = default;
    optional_null& operator=(const optional_null& value) {
        std::optional<T>::operator=(value);
        return *this;
    }
    optional_null& operator=(optional_null&& value) {
        std::optional<T>::operator=(std::move(value));
        return *this;
    }
};
template<typename T>
struct is_optional_null : std::false_type {};
template<typename T>
struct is_optional_null<optional_null<T>> : std::true_type {};

class JsonHelper {
public:
    template<typename T>
    static T deserialize(const Poco::Dynamic::Var& element) {
        if constexpr (is_vector<T>::value) {
            return JsonHelper::deserializeArray<typename T::value_type>(element);
        } else if constexpr (is_optional<T>::value) {
            return JsonHelper::deserializeOptional<typename T::value_type>(element);
        } else if constexpr (is_optional_null<T>::value) {
            return JsonHelper::deserializeOptionalNull<typename T::value_type>(element);
        } else if constexpr (is_unordered_map<T>::value) {
            return JsonHelper::deserializeUnorderedMap<typename T::mapped_type>(element);
        }  else if constexpr (is_map<T>::value) {
            return JsonHelper::deserializeMap<typename T::mapped_type>(element);
        } else {
            if(element.type() != typeid(Poco::JSON::Object::Ptr)) {
                LOG_WARN("Failed to Parse JSON Object, received '" + std::string(element.type().name()) + "'")
                throw JSONParseException("Failed to Parse JSON Object, received '" + std::string(element.type().name()) + "'");
            }
            return T::fromJSON(element.extract<Poco::JSON::Object::Ptr>());
        }
    }
    template<typename T>
    static std::vector<T> deserializeArray(const Poco::Dynamic::Var& array) {
        std::vector<T> result;
        if(array.type() != typeid(Poco::JSON::Array::Ptr)) {
            LOG_WARN("Failed to Parse JSON array, received '" + std::string(array.type().name()) + "'")
            throw JSONParseException("Failed to Parse JSON array, recived '" + std::string(array.type().name()) + "'");
        }
        for(const Poco::Dynamic::Var& element : *(array.extract<Poco::JSON::Array::Ptr>())) result.push_back(JsonHelper::deserialize<T>(element));
        return result;
    }
    template<typename T>
    static std::optional<T> deserializeOptional(const Poco::Dynamic::Var& element) {
        if(element.isEmpty()) return std::nullopt;
        return JsonHelper::deserialize<T>(element);
    }
    template<typename T>
    static optional_null<T> deserializeOptionalNull(const Poco::Dynamic::Var& element) {
        if(element.isEmpty()) return std::nullopt;
        return JsonHelper::deserialize<T>(element);
    }
    template<typename V>
    static std::unordered_map<std::string, V> deserializeUnorderedMap(const Poco::Dynamic::Var& element) {
        std::unordered_map<std::string, V> result;
        if(element.type() != typeid(Poco::JSON::Object::Ptr)) {
            LOG_WARN("Failed to Parse JSON map, received '" + std::string(element.type().name()) + "'")
            throw JSONParseException("Failed to Parse JSON map, received '" + std::string(element.type().name()) + "'");
        }
        for(const auto& kv : *element.extract<Poco::JSON::Object::Ptr>())
            result[kv.first] = JsonHelper::deserialize<V>(kv.second);
        return result;
    }template<typename V>
    static std::map<std::string, V> deserializeMap(const Poco::Dynamic::Var& element) {
        std::map<std::string, V> result;
        if(element.type() != typeid(Poco::JSON::Object::Ptr)) {
            LOG_WARN("Failed to Parse JSON map, received '" + std::string(element.type().name()) + "'")
            throw JSONParseException("Failed to Parse JSON map, received '" + std::string(element.type().name()) + "'");
        }
        for(const auto& kv : *element.extract<Poco::JSON::Object::Ptr>())
            result[kv.first] = JsonHelper::deserialize<V>(kv.second);
        return result;
    }
    template<typename T>
    static std::optional<std::vector<T>> deserializeOptionalArray(const Poco::Dynamic::Var& element) {
        if(element.isEmpty()) return std::nullopt;
        return JsonHelper::deserializeArray<T>(element);
    }

    template<typename T>
    static Poco::Dynamic::Var serialize(const T& element) {
        if constexpr (is_vector<T>::value) {
            Poco::JSON::Array::Ptr array(new Poco::JSON::Array());
            for(const auto& e : element) {array->add(JsonHelper::serialize(e));}
            return Poco::Dynamic::Var(array);
        } else if constexpr (is_optional<T>::value) {
            if(!element.has_value()) return Poco::Dynamic::Var();
            return JsonHelper::serialize(element.value());
        } else if constexpr (is_optional_null<T>::value) {
            if(!element.has_value()) return Poco::Dynamic::Var();
            return JsonHelper::serialize(element.value());
        } else if constexpr (is_unordered_map<T>::value || is_map<T>::value)   {
            Poco::JSON::Object::Ptr object(new Poco::JSON::Object());
            for(const auto& kv : element) {object->set(kv.first, JsonHelper::serialize(kv.second));}
            return Poco::Dynamic::Var(object);
        } else {
            return Poco::Dynamic::Var(element.toJSON());
        }
    }
};
template<>
inline Poco::Dynamic::Var JsonHelper::deserialize<Poco::Dynamic::Var>(const Poco::Dynamic::Var& element) {
    return element;
};
template<>
inline Poco::JSON::Object::Ptr JsonHelper::deserialize<Poco::JSON::Object::Ptr>(const Poco::Dynamic::Var& element) {
    if(element.type() != typeid(Poco::JSON::Object::Ptr)) {
        LOG_WARN("Failed to Parse JSON Object value, recived '" + std::string(element.type().name()) + "'")
        throw JSONParseException("Failed to Parse JSON Object value, recived '" + std::string(element.type().name()) + "'");
    }
    return element.extract<Poco::JSON::Object::Ptr>();
};
template<>
inline Pson::BinaryString JsonHelper::deserialize<Pson::BinaryString>(const Poco::Dynamic::Var& element) {
    if(!element.isString()) {
        LOG_WARN("Failed to Parse JSON BinaryString value, recived '" + std::string(element.type().name()) + "'")
        throw JSONParseException("Failed to Parse JSON BinaryString value, recived '" + std::string(element.type().name()) + "'");
    }
    return Pson::BinaryString(element.convert<std::string>());
};
template<>
inline std::string JsonHelper::deserialize<std::string>(const Poco::Dynamic::Var& element) {
    if(!element.isString()) {
        LOG_WARN("Failed to Parse JSON String value, recived '" + std::string(element.type().name()) + "'")
        throw JSONParseException("Failed to Parse JSON String value, recived '" + std::string(element.type().name()) + "'");
    }
    return element.convert<std::string>();
};
template<>
inline int64_t JsonHelper::deserialize<int64_t>(const Poco::Dynamic::Var& element) {
    if(!element.isInteger()) {
        LOG_WARN("Failed to Parse JSON Integer value, recived '" + std::string(element.type().name()) + "'")
        throw JSONParseException("Failed to Parse JSON Integer value, recived '" + std::string(element.type().name()) + "'");
    }
    return element.convert<int64_t>();
};
template<>
inline bool JsonHelper::deserialize<bool>(const Poco::Dynamic::Var& element) {
    if(!element.isBoolean()) {
        LOG_WARN("Failed to Parse JSON boolean value, recived '" + std::string(element.type().name()) + "'")
        throw JSONParseException("Failed to Parse JSON boolean value, recived '" + std::string(element.type().name()) + "'");
    }
    return element.convert<bool>();
};
template<>
inline Poco::Dynamic::Var JsonHelper::serialize<Poco::Dynamic::Var>(const Poco::Dynamic::Var& element) {
    return Poco::Dynamic::Var(element);
};
template<>
inline Poco::Dynamic::Var JsonHelper::serialize<Poco::JSON::Object::Ptr>(const Poco::JSON::Object::Ptr& element) {
    return Poco::Dynamic::Var(Poco::Dynamic::Var(element));
};
template<>
inline Poco::Dynamic::Var JsonHelper::serialize<Pson::BinaryString>(const Pson::BinaryString& element) {
    return Poco::Dynamic::Var(Poco::Dynamic::Var(element));
};
template<>
inline Poco::Dynamic::Var JsonHelper::serialize<std::string>(const std::string& element) {
    return Poco::Dynamic::Var(Poco::Dynamic::Var(element));
};
template<>
inline Poco::Dynamic::Var JsonHelper::serialize<int64_t>(const int64_t& element) {
    return Poco::Dynamic::Var(Poco::Dynamic::Var(element));
};
template<>
inline Poco::Dynamic::Var JsonHelper::serialize<bool>(const bool& element) {
    return Poco::Dynamic::Var(Poco::Dynamic::Var(element));
};

// Internal helpers — not for direct use
// F(NAME, TYPE) — name first, type last (variadic to support template types with commas, e.g. std::map<K,V>)
#define _JSON_DECL(NAME, ...) __VA_ARGS__ NAME;
#define _JSON_FROM(NAME, ...) NAME = privmx::utils::JsonHelper::deserialize<__VA_ARGS__>(JSON->has(#NAME) ? JSON->get(#NAME) : Poco::Dynamic::Var());
#define _JSON_TO(NAME, ...)   {\
    if constexpr (privmx::utils::is_optional<__VA_ARGS__>::value) {\
        auto __value = privmx::utils::JsonHelper::serialize<__VA_ARGS__>(NAME);\
        if(!__value.isEmpty()) {result->set(#NAME, __value);}\
    } else {\
        result->set(#NAME, privmx::utils::JsonHelper::serialize<__VA_ARGS__>(NAME));\
    }\
}

// Generate a JsonCompatable struct from an X-macro field list.
// Usage:
//   #define MY_FIELDS(F) F(foo, std::string) F(bar, int64_t)
//   JSON_STRUCT(MyStruct, MY_FIELDS);
#define JSON_STRUCT(STRUCT_NAME, FIELDS) \
struct STRUCT_NAME { \
    FIELDS(_JSON_DECL) \
    static STRUCT_NAME fromJSON(Poco::Dynamic::Var JSON_Var) { \
        if(JSON_Var.type() != typeid(Poco::JSON::Object::Ptr)) throw privmx::utils::JSONParseException("Failed to Parse JSON Object value, recived '" + std::string(JSON_Var.type().name()) + "'"); \
        STRUCT_NAME obj; \
        obj._parseFields(JSON_Var.extract<Poco::JSON::Object::Ptr>()); \
        return obj; \
    } \
    static STRUCT_NAME fromJSON(Poco::JSON::Object::Ptr JSON) { \
        STRUCT_NAME obj; \
        obj._parseFields(JSON); \
        return obj; \
    } \
    Poco::JSON::Object::Ptr toJSON() const { \
        Poco::JSON::Object::Ptr result(new Poco::JSON::Object()); \
        serializeFields(result); \
        return result; \
    } \
protected: \
    void _parseFields(Poco::JSON::Object::Ptr JSON) { FIELDS(_JSON_FROM) } \
    void serializeFields([[maybe_unused]] Poco::JSON::Object::Ptr result) const { FIELDS(_JSON_TO) } \
};

// Extend a JSON_STRUCT with additional fields. Chains to base deserialization/serialization.
// Usage:
//   #define EXTRA_FIELDS(F) F(extra, std::string)
//   JSON_STRUCT_EXT(Derived, Base, EXTRA_FIELDS);
#define JSON_STRUCT_EXT(STRUCT_NAME, BASE_NAME, FIELDS) \
struct STRUCT_NAME : public BASE_NAME { \
    FIELDS(_JSON_DECL) \
    static STRUCT_NAME fromJSON(Poco::Dynamic::Var JSON_Var) { \
        if(JSON_Var.type() != typeid(Poco::JSON::Object::Ptr)) throw privmx::utils::JSONParseException("Failed to Parse JSON Object value, recived '" + std::string(JSON_Var.type().name()) + "'"); \
        STRUCT_NAME obj; \
        obj._parseFields(JSON_Var.extract<Poco::JSON::Object::Ptr>()); \
        return obj; \
    } \
    static STRUCT_NAME fromJSON(Poco::JSON::Object::Ptr JSON) { \
        STRUCT_NAME obj; \
        obj._parseFields(JSON); \
        return obj; \
    } \
    Poco::JSON::Object::Ptr toJSON() const { \
        Poco::JSON::Object::Ptr result(new Poco::JSON::Object()); \
        BASE_NAME::serializeFields(result); \
        serializeFields(result); \
        return result; \
    } \
protected: \
    void _parseFields(Poco::JSON::Object::Ptr JSON) { \
        BASE_NAME::_parseFields(JSON); \
        FIELDS(_JSON_FROM) \
    } \
    void serializeFields([[maybe_unused]] Poco::JSON::Object::Ptr result) const { FIELDS(_JSON_TO) } \
}

} // utils
} // privmx

#endif // _PRIVMXLIB_UTILS_JSON_HELPER_HPP_
