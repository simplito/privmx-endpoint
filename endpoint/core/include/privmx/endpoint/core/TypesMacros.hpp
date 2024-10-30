#ifndef _PRIVMXLIB_ENDPOINT_CORE_TYPESMACROS_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_TYPESMACROS_HPP_

#include <privmx/utils/TypesMacros.hpp>
#include <privmx/utils/TypedObject.hpp>

//-------------------------------------CONSTRUCTOR(NAME)------------------------------------//

#define ENDPOINT_TYPE_CONSTRUCTOR(NAME) \
    TYPE_CONSTRUCTOR(NAME, false, false)

#define ENDPOINT_TYPE_CONSTRUCTOR_INHERIT(NAME, PARENT) \
    TYPE_CONSTRUCTOR_INHERIT(NAME, PARENT, false, false)

//-------------------------------------CONSTRUCTOR_2(NAMESPACE, NAME)------------------------------------//

#define ENDPOINT_TYPE_CONSTRUCTOR_2(NAMESPACE, NAME) \
    TYPE_CONSTRUCTOR_WITH_NAMESPACE(NAMESPACE, NAME, false, false)

#define ENDPOINT_TYPE_CONSTRUCTOR_INHERIT_2(NAMESPACE, NAME, PARENT) \
    TYPE_CONSTRUCTOR_WITH_NAMESPACE_INHERIT(NAMESPACE, NAME, PARENT, false, false)

//-------------------------------------ENDPOINT_TYPE(NAME)------------------------------------//


//No Namespace
#define ENDPOINT_TYPE(NAME) \
class NAME : public utils::TypedObject \
{ \
public: \
    ENDPOINT_TYPE_CONSTRUCTOR(NAME) \
    void initialize() override {initializeObject({});}

#define ENDPOINT_TYPE_INHERIT(NAME, PARENT) \
class NAME : public PARENT \
{ \
public: \
    ENDPOINT_TYPE_CONSTRUCTOR_INHERIT(NAME, PARENT) \
    void initialize() override {initializeObject({});}

//--- SERVER ----//

//-------------------------------------CONSTRUCTOR(NAME)------------------------------------//

#define ENDPOINT_SERVER_TYPE_CONSTRUCTOR(NAME) \
    TYPE_CONSTRUCTOR(NAME, false, false)

#define ENDPOINT_SERVER_TYPE_CONSTRUCTOR_INHERIT(NAME, PARENT) \
    TYPE_CONSTRUCTOR_INHERIT(NAME, PARENT, false, false)

//-------------------------------------CONSTRUCTOR_2(NAMESPACE, NAME)------------------------------------//

#define ENDPOINT_SERVER_TYPE_CONSTRUCTOR_2(NAMESPACE, NAME) \
    TYPE_CONSTRUCTOR_WITH_NAMESPACE(NAMESPACE, NAME, false, false)

#define ENDPOINT_SERVER_TYPE_CONSTRUCTOR_INHERIT_2(NAMESPACE, NAME, PARENT) \
    TYPE_CONSTRUCTOR_WITH_NAMESPACE_INHERIT(NAMESPACE, NAME, PARENT, false, false)

//-------------------------------------ENDPOINT_TYPE(NAME)------------------------------------//


//No Namespace
#define ENDPOINT_SERVER_TYPE(NAME) \
class NAME : public utils::TypedObject \
{ \
public: \
    ENDPOINT_SERVER_TYPE_CONSTRUCTOR(NAME) \
    void initialize() override {initializeObject({});}

#define ENDPOINT_SERVER_TYPE_INHERIT(NAME, PARENT) \
class NAME : public PARENT \
{ \
public: \
    ENDPOINT_SERVER_TYPE_CONSTRUCTOR_INHERIT(NAME, PARENT) \
    void initialize() override {initializeObject({});}

//--- CLIENT ----//

//-------------------------------------CONSTRUCTOR(NAME)------------------------------------//

#define ENDPOINT_CLIENT_TYPE_CONSTRUCTOR(NAME) \
    TYPE_CORE_CONSTRUCTOR(NAME, false)

#define ENDPOINT_CLIENT_TYPE_CONSTRUCTOR_INHERIT(NAME, PARENT) \
    TYPE_CORE_CONSTRUCTOR_INHERIT(NAME, PARENT, false)

//-------------------------------------CONSTRUCTOR_2(NAMESPACE, NAME)------------------------------------//

#define ENDPOINT_CLIENT_TYPE_CONSTRUCTOR_2(NAMESPACE, NAME) \
    TYPE_CORE_CONSTRUCTOR_WITH_NAMESPACE(NAMESPACE, NAME, false)

#define ENDPOINT_CLIENT_TYPE_CONSTRUCTOR_INHERIT_2(NAMESPACE, NAME, PARENT) \
    TYPE_CORE_CONSTRUCTOR_WITH_NAMESPACE_INHERIT(NAMESPACE, NAME, PARENT, false)

//-------------------------------------ENDPOINT_TYPE(NAME)------------------------------------//


//No Namespace
#define ENDPOINT_CLIENT_TYPE(NAME) \
class NAME : public utils::TypedObject \
{ \
public: \
    ENDPOINT_CLIENT_TYPE_CONSTRUCTOR(NAME) \
    void initialize() override {initializeObject({});}

#define ENDPOINT_CLIENT_TYPE_INHERIT(NAME, PARENT) \
class NAME : public PARENT \
{ \
public: \
    ENDPOINT_CLIENT_TYPE_CONSTRUCTOR_INHERIT(NAME, PARENT) \
    void initialize() override {initializeObject({});}

#endif // _PRIVMXLIB_ENDPOINT_CORE_TYPESMACROS_HPP_
