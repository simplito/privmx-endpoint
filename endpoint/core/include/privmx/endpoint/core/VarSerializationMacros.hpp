/*
PrivMX Endpoint.
Copyright © 2026 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_VARSERIALIZATIONMACROS_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_VARSERIALIZATIONMACROS_HPP_

#include <Poco/JSON/Object.h>

#include "privmx/endpoint/core/TypeValidator.hpp"
#include "privmx/endpoint/core/VarDeserializer.hpp"
#include "privmx/endpoint/core/VarSerializer.hpp"

// ---------------------------------------------------------------------------
// Internal helpers — single-field operations
// ---------------------------------------------------------------------------

#define _VAR_SER_FIELD(f)   obj->set(#f, serialize(val.f));
#define _VAR_DESER_FIELD(f) deserialize(obj->get(#f), name + "." #f, out.f);

// ---------------------------------------------------------------------------
// Serialize — explicit per-count macros (1–20)
// Each _VAR_SER_N processes its first argument and delegates the rest to N-1.
// ---------------------------------------------------------------------------

// clang-format off
#define _VAR_SER_1(a)       _VAR_SER_FIELD(a)
#define _VAR_SER_2(a, b)    _VAR_SER_FIELD(a)  _VAR_SER_1(b)
#define _VAR_SER_3(a, ...)  _VAR_SER_FIELD(a)  _VAR_SER_2(__VA_ARGS__)
#define _VAR_SER_4(a, ...)  _VAR_SER_FIELD(a)  _VAR_SER_3(__VA_ARGS__)
#define _VAR_SER_5(a, ...)  _VAR_SER_FIELD(a)  _VAR_SER_4(__VA_ARGS__)
#define _VAR_SER_6(a, ...)  _VAR_SER_FIELD(a)  _VAR_SER_5(__VA_ARGS__)
#define _VAR_SER_7(a, ...)  _VAR_SER_FIELD(a)  _VAR_SER_6(__VA_ARGS__)
#define _VAR_SER_8(a, ...)  _VAR_SER_FIELD(a)  _VAR_SER_7(__VA_ARGS__)
#define _VAR_SER_9(a, ...)  _VAR_SER_FIELD(a)  _VAR_SER_8(__VA_ARGS__)
#define _VAR_SER_10(a, ...) _VAR_SER_FIELD(a)  _VAR_SER_9(__VA_ARGS__)
#define _VAR_SER_11(a, ...) _VAR_SER_FIELD(a)  _VAR_SER_10(__VA_ARGS__)
#define _VAR_SER_12(a, ...) _VAR_SER_FIELD(a)  _VAR_SER_11(__VA_ARGS__)
#define _VAR_SER_13(a, ...) _VAR_SER_FIELD(a)  _VAR_SER_12(__VA_ARGS__)
#define _VAR_SER_14(a, ...) _VAR_SER_FIELD(a)  _VAR_SER_13(__VA_ARGS__)
#define _VAR_SER_15(a, ...) _VAR_SER_FIELD(a)  _VAR_SER_14(__VA_ARGS__)
#define _VAR_SER_16(a, ...) _VAR_SER_FIELD(a)  _VAR_SER_15(__VA_ARGS__)
#define _VAR_SER_17(a, ...) _VAR_SER_FIELD(a)  _VAR_SER_16(__VA_ARGS__)
#define _VAR_SER_18(a, ...) _VAR_SER_FIELD(a)  _VAR_SER_17(__VA_ARGS__)
#define _VAR_SER_19(a, ...) _VAR_SER_FIELD(a)  _VAR_SER_18(__VA_ARGS__)
#define _VAR_SER_20(a, ...) _VAR_SER_FIELD(a)  _VAR_SER_19(__VA_ARGS__)

#define _VAR_SER_GET(_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,_11,_12,_13,_14,_15,_16,_17,_18,_19,_20, NAME, ...) NAME
#define _VAR_SER_FIELDS(...) \
    _VAR_SER_GET(__VA_ARGS__, \
        _VAR_SER_20,_VAR_SER_19,_VAR_SER_18,_VAR_SER_17,_VAR_SER_16, \
        _VAR_SER_15,_VAR_SER_14,_VAR_SER_13,_VAR_SER_12,_VAR_SER_11, \
        _VAR_SER_10,_VAR_SER_9,_VAR_SER_8,_VAR_SER_7,_VAR_SER_6, \
        _VAR_SER_5,_VAR_SER_4,_VAR_SER_3,_VAR_SER_2,_VAR_SER_1)(__VA_ARGS__)

// ---------------------------------------------------------------------------
// Deserialize — explicit per-count macros (1–20)
// ---------------------------------------------------------------------------

#define _VAR_DESER_1(a)       _VAR_DESER_FIELD(a)
#define _VAR_DESER_2(a, b)    _VAR_DESER_FIELD(a)  _VAR_DESER_1(b)
#define _VAR_DESER_3(a, ...)  _VAR_DESER_FIELD(a)  _VAR_DESER_2(__VA_ARGS__)
#define _VAR_DESER_4(a, ...)  _VAR_DESER_FIELD(a)  _VAR_DESER_3(__VA_ARGS__)
#define _VAR_DESER_5(a, ...)  _VAR_DESER_FIELD(a)  _VAR_DESER_4(__VA_ARGS__)
#define _VAR_DESER_6(a, ...)  _VAR_DESER_FIELD(a)  _VAR_DESER_5(__VA_ARGS__)
#define _VAR_DESER_7(a, ...)  _VAR_DESER_FIELD(a)  _VAR_DESER_6(__VA_ARGS__)
#define _VAR_DESER_8(a, ...)  _VAR_DESER_FIELD(a)  _VAR_DESER_7(__VA_ARGS__)
#define _VAR_DESER_9(a, ...)  _VAR_DESER_FIELD(a)  _VAR_DESER_8(__VA_ARGS__)
#define _VAR_DESER_10(a, ...) _VAR_DESER_FIELD(a)  _VAR_DESER_9(__VA_ARGS__)
#define _VAR_DESER_11(a, ...) _VAR_DESER_FIELD(a)  _VAR_DESER_10(__VA_ARGS__)
#define _VAR_DESER_12(a, ...) _VAR_DESER_FIELD(a)  _VAR_DESER_11(__VA_ARGS__)
#define _VAR_DESER_13(a, ...) _VAR_DESER_FIELD(a)  _VAR_DESER_12(__VA_ARGS__)
#define _VAR_DESER_14(a, ...) _VAR_DESER_FIELD(a)  _VAR_DESER_13(__VA_ARGS__)
#define _VAR_DESER_15(a, ...) _VAR_DESER_FIELD(a)  _VAR_DESER_14(__VA_ARGS__)
#define _VAR_DESER_16(a, ...) _VAR_DESER_FIELD(a)  _VAR_DESER_15(__VA_ARGS__)
#define _VAR_DESER_17(a, ...) _VAR_DESER_FIELD(a)  _VAR_DESER_16(__VA_ARGS__)
#define _VAR_DESER_18(a, ...) _VAR_DESER_FIELD(a)  _VAR_DESER_17(__VA_ARGS__)
#define _VAR_DESER_19(a, ...) _VAR_DESER_FIELD(a)  _VAR_DESER_18(__VA_ARGS__)
#define _VAR_DESER_20(a, ...) _VAR_DESER_FIELD(a)  _VAR_DESER_19(__VA_ARGS__)

#define _VAR_DESER_GET(_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,_11,_12,_13,_14,_15,_16,_17,_18,_19,_20, NAME, ...) NAME
#define _VAR_DESER_FIELDS(...) \
    _VAR_DESER_GET(__VA_ARGS__, \
        _VAR_DESER_20,_VAR_DESER_19,_VAR_DESER_18,_VAR_DESER_17,_VAR_DESER_16, \
        _VAR_DESER_15,_VAR_DESER_14,_VAR_DESER_13,_VAR_DESER_12,_VAR_DESER_11, \
        _VAR_DESER_10,_VAR_DESER_9,_VAR_DESER_8,_VAR_DESER_7,_VAR_DESER_6, \
        _VAR_DESER_5,_VAR_DESER_4,_VAR_DESER_3,_VAR_DESER_2,_VAR_DESER_1)(__VA_ARGS__)
// clang-format on

// ---------------------------------------------------------------------------
// Public macro
// ---------------------------------------------------------------------------

/**
 * Generates inline VarSerializer::serialize<Name> and
 * VarDeserializer::deserialize<Name> template specialisations for a
 * plain-struct type whose every field already has its own serialisation pair.
 *
 * Usage (at file scope, after struct definition):
 *
 *   struct ItemPOD {
 *       std::string id;
 *       int64_t     size;
 *   };
 *   VAR_DEFINE_TYPE(ItemPOD, id, size)
 *
 * Supports 1–20 fields.
 * The "__type" string written to the JSON object equals #Name.
 */
#define VAR_DEFINE_TYPE(Name, ...)                                                                  \
    template<>                                                                                      \
    inline Poco::Dynamic::Var                                                                       \
    privmx::endpoint::core::VarSerializer::serialize<Name>(const Name& val) {    \
        Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();                                     \
        if (_options.addType) { obj->set("__type", #Name); }                                        \
        _VAR_SER_FIELDS(__VA_ARGS__)                                                                \
        return obj;                                                                                 \
    }                                                                                               \
    template<>                                                                                      \
    inline void                                                                                     \
    privmx::endpoint::core::VarDeserializer::deserialize<Name>(                                   \
            const Poco::Dynamic::Var& val, const std::string& name, Name& out) {                    \
        TypeValidator::validateObject(val, name);                                                   \
        Poco::JSON::Object::Ptr obj = val.extract<Poco::JSON::Object::Ptr>();                       \
        _VAR_DESER_FIELDS(__VA_ARGS__)                                                              \
    }

#endif  // _PRIVMXLIB_ENDPOINT_CORE_VARSERIALIZATIONMACROS_HPP_
