#ifndef _PRIVMXLIB_UTILS_TYPESMACROS_HPP_
#define _PRIVMXLIB_UTILS_TYPESMACROS_HPP_

#include <optional>
//-----------------------------------UNIVERSAL CONSTRUCTOR(NAME)----------------------------------//
// STD
#define TYPE_CONSTRUCTOR(NAME, ADD_NUULS_BOOL, ADD_TYPE_BOOL) \
NAME() {} \
NAME(const Poco::Dynamic::Var& obj) : utils::TypedObject(obj, ADD_NUULS_BOOL, ADD_TYPE_BOOL, #NAME) {} \
NAME(const Poco::Dynamic::Var& obj, bool add_nulls, bool add_type, const std::string &type) : utils::TypedObject(obj, add_nulls, add_type, type) {} \
NAME(const Poco::JSON::Object::Ptr& obj) : utils::TypedObject(obj, ADD_NUULS_BOOL, ADD_TYPE_BOOL, #NAME) {} \
NAME(const Poco::JSON::Object::Ptr& obj, bool add_nulls, bool add_type, const std::string &type) : utils::TypedObject(obj, add_nulls, add_type, type) {} \
NAME copy() { return NAME( this->copyObject() ); }

#define TYPE_CONSTRUCTOR_INHERIT(NAME, PARENT, ADD_NUULS_BOOL, ADD_TYPE_BOOL) \
NAME() {} \
NAME(const Poco::Dynamic::Var& obj) : PARENT(obj, ADD_NUULS_BOOL, ADD_TYPE_BOOL, #NAME) {} \
NAME(const Poco::Dynamic::Var& obj, bool add_nulls, bool add_type, const std::string &type) : PARENT(obj, add_nulls, add_type, type) {} \
NAME(const Poco::JSON::Object::Ptr& obj) : PARENT(obj, ADD_NUULS_BOOL, ADD_TYPE_BOOL, #NAME) {} \
NAME(const Poco::JSON::Object::Ptr& obj, bool add_nulls, bool add_type, const std::string &type) : PARENT(obj, add_nulls, add_type, type) {} \
NAME copy() { return NAME( this->copyObject() ); }

#define TYPE_CONSTRUCTOR_WITH_NAMESPACE(NAMESPACE, NAME, ADD_NUULS_BOOL, ADD_TYPE_BOOL) \
NAME() {} \
NAME(const Poco::Dynamic::Var& obj) : utils::TypedObject(obj, ADD_NUULS_BOOL, ADD_TYPE_BOOL, (std::string)#NAMESPACE + "_" + (std::string)#NAME) {} \
NAME(const Poco::Dynamic::Var& obj, bool add_nulls, bool add_type, const std::string &type) : utils::TypedObject(obj, add_nulls, add_type, type) {} \
NAME(const Poco::JSON::Object::Ptr& obj) : utils::TypedObject(obj, ADD_NUULS_BOOL, ADD_TYPE_BOOL, (std::string)#NAMESPACE + "_" + (std::string)#NAME) {} \
NAME(const Poco::JSON::Object::Ptr& obj, bool add_nulls, bool add_type, const std::string &type) : utils::TypedObject(obj, add_nulls, add_type, type) {} \
NAME copy() { return NAME( this->copyObject() ); }

#define TYPE_CONSTRUCTOR_WITH_NAMESPACE_INHERIT(NAMESPACE, NAME, PARENT, ADD_NUULS_BOOL, ADD_TYPE_BOOL) \
NAME() {} \
NAME(const Poco::Dynamic::Var& obj) : PARENT(obj, ADD_NUULS_BOOL, ADD_TYPE_BOOL, (std::string)#NAMESPACE + "_" + (std::string)#NAME) {} \
NAME(const Poco::Dynamic::Var& obj, bool add_nulls, bool add_type, const std::string &type) : PARENT(obj, add_nulls, add_type, type) {} \
NAME(const Poco::JSON::Object::Ptr& obj) : PARENT(obj, ADD_NUULS_BOOL, ADD_TYPE_BOOL, (std::string)#NAMESPACE + "_" + (std::string)#NAME) {} \
NAME(const Poco::JSON::Object::Ptr& obj, bool add_nulls, bool add_type, const std::string &type) : PARENT(obj, add_nulls, add_type, type) {} \
NAME copy() { return NAME( this->copyObject() ); }

// CORE
#define TYPE_CORE_CONSTRUCTOR(NAME, ADD_NUULS_BOOL) \
NAME() {} \
NAME(const Poco::Dynamic::Var& obj) : utils::TypedObject(obj, ADD_NUULS_BOOL, false, "") {} \
NAME(const Poco::Dynamic::Var& obj, bool add_nulls, bool add_type, const std::string &type) : utils::TypedObject(obj, add_nulls, add_type, type) {} \
NAME(const Poco::JSON::Object::Ptr& obj) : utils::TypedObject(obj, ADD_NUULS_BOOL, false, "") {} \
NAME(const Poco::JSON::Object::Ptr& obj, bool add_nulls, bool add_type, const std::string &type) : utils::TypedObject(obj, add_nulls, add_type, type) {} \
NAME copy() { return NAME( this->copyObject() ); }

#define TYPE_CORE_CONSTRUCTOR_INHERIT(NAME, PARENT, ADD_NUULS_BOOL) \
NAME() {} \
NAME(const Poco::Dynamic::Var& obj) : PARENT(obj, ADD_NUULS_BOOL, false, "") {} \
NAME(const Poco::Dynamic::Var& obj, bool add_nulls, bool add_type, const std::string &type) : PARENT(obj, add_nulls, add_type, type) {} \
NAME(const Poco::JSON::Object::Ptr& obj) : PARENT(obj, ADD_NUULS_BOOL, false, "") {} \
NAME(const Poco::JSON::Object::Ptr& obj, bool add_nulls, bool add_type, const std::string &type) : PARENT(obj, add_nulls, add_type, type) {} \
NAME copy() { return NAME( this->copyObject() ); }

#define TYPE_CORE_CONSTRUCTOR_WITH_NAMESPACE(NAMESPACE, NAME, ADD_NUULS_BOOL) \
NAME() {} \
NAME(const Poco::Dynamic::Var& obj) : utils::TypedObject(obj, ADD_NUULS_BOOL, false, "") {} \
NAME(const Poco::Dynamic::Var& obj, bool add_nulls, bool add_type, const std::string &type) : utils::TypedObject(obj, add_nulls, add_type, type) {} \
NAME(const Poco::JSON::Object::Ptr& obj) : utils::TypedObject(obj, ADD_NUULS_BOOL, false, "") {} \
NAME(const Poco::JSON::Object::Ptr& obj, bool add_nulls, bool add_type, const std::string &type) : utils::TypedObject(obj, add_nulls, add_type, type) {} \
NAME copy() { return NAME( this->copyObject() ); }

#define TYPE_CORE_CONSTRUCTOR_WITH_NAMESPACE_INHERIT(NAMESPACE, NAME, PARENT, ADD_NUULS_BOOL) \
NAME() {} \
NAME(const Poco::Dynamic::Var& obj) : PARENT(obj, ADD_NUULS_BOOL, false, "") {} \
NAME(const Poco::Dynamic::Var& obj, bool add_nulls, bool add_type, const std::string &type) : PARENT(obj, add_nulls, add_type, type) {} \
NAME(const Poco::JSON::Object::Ptr& obj) : PARENT(obj, ADD_NUULS_BOOL, false, "") {} \
NAME(const Poco::JSON::Object::Ptr& obj, bool add_nulls, bool add_type, const std::string &type) : PARENT(obj, add_nulls, add_type, type) {} \
NAME copy() { return NAME( this->copyObject() ); }


//-------------------------------------CONSTRUCTOR(NAME)------------------------------------//

#define SERVER_TYPE_CONSTRUCTOR(NAME) \
    TYPE_CORE_CONSTRUCTOR(NAME, false)

#define SERVER_TYPE_CONSTRUCTOR_INHERIT(NAME, PARENT) \
    TYPE_CORE_CONSTRUCTOR_INHERIT(NAME, PARENT, false)

#define CORE_TYPE_CONSTRUCTOR(NAME) \
    TYPE_CORE_CONSTRUCTOR(NAME, false)

#define CORE_TYPE_CONSTRUCTOR_INHERIT(NAME, PARENT) \
    TYPE_CORE_CONSTRUCTOR_INHERIT(NAME, PARENT, false)

#define API_TYPE_CONSTRUCTOR(NAME) \
    TYPE_CONSTRUCTOR(NAME, true, true)

#define API_TYPE_CONSTRUCTOR_INHERIT(NAME, PARENT) \
    TYPE_CONSTRUCTOR_INHERIT(NAME, true, true)

//-------------------------------------CONSTRUCTOR_2(NAMESPACE, NAME)------------------------------------//

#define SERVER_TYPE_CONSTRUCTOR_2(NAMESPACE, NAME) \
    TYPE_CORE_CONSTRUCTOR_WITH_NAMESPACE(NAMESPACE, NAME, false)

#define SERVER_TYPE_CONSTRUCTOR_INHERIT_2(NAMESPACE, NAME, PARENT) \
    TYPE_CORE_CONSTRUCTOR_WITH_NAMESPACE_INHERIT(NAMESPACE, NAME, PARENT, false)    

#define CORE_TYPE_CONSTRUCTOR_2(NAMESPACE, NAME) \
    TYPE_CORE_CONSTRUCTOR_WITH_NAMESPACE(NAMESPACE, NAME, false)

#define CORE_TYPE_CONSTRUCTOR_INHERIT_2(NAMESPACE, NAME, PARENT) \
    TYPE_CORE_CONSTRUCTOR_WITH_NAMESPACE_INHERIT(NAMESPACE, NAME, PARENT, false)   

#define API_TYPE_CONSTRUCTOR_2(NAMESPACE, NAME) \
    TYPE_CONSTRUCTOR_WITH_NAMESPACE(NAMESPACE, NAME, true, true)

#define API_TYPE_CONSTRUCTOR_INHERIT_2(NAMESPACE, NAME, PARENT) \
    TYPE_CONSTRUCTOR_WITH_NAMESPACE_INHERIT(NAMESPACE, NAME, PARENT, true, true)   



//-------------------------------------DECLARE_TYPE(NAMESPACE, NAME)------------------------------------//

#define DECLARE_SERVER_TYPE(NAME) \
class NAME : public utils::TypedObject \
{ \
public: \
    SERVER_TYPE_CONSTRUCTOR_2(server, NAME) \
    void initialize() override {}

#define DECLARE_SERVER_TYPE_INHERIT(NAME, PARENT) \
class NAME : public PARENT \
{ \
public: \
    SERVER_TYPE_CONSTRUCTOR_INHERIT_2(server, NAME, PARENT) \
    void initialize() override {}

#define DECLARE_CORE_TYPE(NAME) \
class NAME : public utils::TypedObject \
{ \
public: \
    CORE_TYPE_CONSTRUCTOR_2(core, NAME) \
    void initialize() override {}

#define DECLARE_CORE_TYPE_INHERIT(NAME, PARENT) \
class NAME : public PARENT \
{ \
public: \
    SERVER_TYPE_CONSTRUCTOR_INHERIT_2(core, NAME, PARENT) \
    void initialize() override {}

#define DECLARE_API_TYPE(NAME) \
class NAME : public utils::TypedObject \
{ \
public: \
    API_TYPE_CONSTRUCTOR_2(api, NAME)

#define DECLARE_API_TYPE_INHERIT(NAME, PARENT) \
class NAME : public PARENT \
{ \
public: \
    API_TYPE_CONSTRUCTOR_INHERIT_2(api, NAME, PARENT)


#define TYPE_END \
};

//-------------------------------------FIELD------------------------------------//

#define BASE_FIELD(NAME, TYPE) \
void NAME(const TYPE& value) { set(#NAME, value); } \
TYPE NAME() const { return get(#NAME).extract<TYPE>(); } \
TYPE NAME ## Opt(const TYPE& opt) { if (isNullOrUndefined(#NAME)) return opt; return NAME(); } \
bool NAME ## Empty() const { return isNullOrUndefined(#NAME); } \
void NAME ## Clear() { set( #NAME, Poco::Dynamic::Var()); }

#define PROBLEMATIC_BASE_FIELD(FIELD_NAME, CLASS_NAME, TYPE) \
void CLASS_NAME(const TYPE& value) { set(#FIELD_NAME, value); } \
TYPE CLASS_NAME() const { return get(#FIELD_NAME).extract<TYPE>(); } \
TYPE CLASS_NAME ## Opt(const TYPE& opt) { if (isNullOrUndefined(#FIELD_NAME)) return opt; return CLASS_NAME(); } \
bool CLASS_NAME ## Empty() const { return isNullOrUndefined(#FIELD_NAME); } \
void CLASS_NAME ## Clear() { set( #FIELD_NAME, Poco::Dynamic::Var()); }

#define STRING_FIELD(NAME) \
void NAME(const std::string& value) { set(#NAME, value); } \
std::string NAME() const { return get(#NAME).extract<std::string>(); } \
std::string NAME ## Opt(const std::string& opt) { if (isNullOrUndefined(#NAME)) return opt; return NAME(); } \
bool NAME ## Empty() const { return isNullOrUndefined(#NAME); } \
void NAME ## Clear() { set( #NAME, Poco::Dynamic::Var()); } \
std::optional<std::string> NAME ## Optional() const { if (isNullOrUndefined(#NAME)) return std::nullopt; return std::make_optional(NAME()); } \
void NAME ## Optional (const std::optional<std::string>& value) { set(#NAME, value.has_value() ? Poco::Dynamic::Var(value.value()) : Poco::Dynamic::Var()); }

#define INT32_FIELD(NAME) \
void NAME(const Poco::Int32& value) { set(#NAME, value); } \
Poco::Int32 NAME() const { return get(#NAME).convert<Poco::Int32>(); } \
Poco::Int32 NAME ## Opt(const Poco::Int32& opt) { if (isNullOrUndefined(#NAME)) return opt; return NAME(); } \
bool NAME ## Empty() const { return isNullOrUndefined(#NAME); } \
void NAME ## Clear() { set( #NAME, Poco::Dynamic::Var()); }

#define INT64_FIELD(NAME) \
void NAME(const Poco::Int64& value) { set(#NAME, value); } \
Poco::Int64 NAME() const { return get(#NAME).convert<Poco::Int64>(); } \
Poco::Int64 NAME ## Opt(const Poco::Int64& opt) { if (isNullOrUndefined(#NAME)) return opt; return NAME(); } \
bool NAME ## Empty() const { return isNullOrUndefined(#NAME); } \
void NAME ## Clear() { set( #NAME, Poco::Dynamic::Var()); }

#define BOOL_FIELD(NAME) \
void NAME(const bool& value) { set(#NAME, value); } \
bool NAME() const { return get(#NAME).template extract<bool>(); } \
bool NAME ## Opt(const bool& opt) const { if (isNullOrUndefined(#NAME)) return opt; return NAME(); } \
bool NAME ## Empty() const { return isNullOrUndefined(#NAME); } \
void NAME ## Clear() { set( #NAME, Poco::Dynamic::Var()); }

#define DOUBLE_FIELD(NAME) \
void NAME(const double& value) { set(#NAME, value); } \
double NAME() const { return get(#NAME).extract<double>(); } \
double NAME ## Opt(const double& opt) { if (isNullOrUndefined(#NAME)) return opt; return NAME(); }\
bool NAME ## Empty() const { return isNullOrUndefined(#NAME); } \
void NAME ## Clear() { set( #NAME, Poco::Dynamic::Var()); }

#define BINARYSTRING_FIELD(NAME) \
void NAME(const Pson::BinaryString& value) { set(#NAME, value); } \
Pson::BinaryString NAME() const { return get(#NAME).convert<Pson::BinaryString>(); } \
Pson::BinaryString NAME ## Opt(const Pson::BinaryString& opt) { if (isNullOrUndefined(#NAME)) return opt; return NAME(); } \
bool NAME ## Empty() const { return isNullOrUndefined(#NAME); } \
void NAME ## Clear() { set( #NAME, Poco::Dynamic::Var()); }

#define OBJECT_PTR_FIELD(NAME) \
void NAME(const Poco::JSON::Object::Ptr& value) { set(#NAME, value); } \
Poco::JSON::Object::Ptr NAME() const { return getObject<Poco::JSON::Object::Ptr>(#NAME); } \
Poco::JSON::Object::Ptr NAME ## Opt(const Poco::JSON::Object::Ptr& opt) { if (isNullOrUndefined(#NAME)) return opt; return NAME(); } \
bool NAME ## Empty() const { return isNullOrUndefined(#NAME); } \
void NAME ## Clear() { set( #NAME, Poco::Dynamic::Var()); }

#define OBJECT_FIELD(NAME, TYPE) \
void NAME(const TYPE& value) { set(#NAME, value); } \
TYPE NAME() const { return getObject<TYPE>(#NAME); } \
TYPE NAME ## Opt(const TYPE& opt) { if (isNullOrUndefined(#NAME)) return opt; return NAME(); } \
bool NAME ## Empty() const { return isNullOrUndefined(#NAME); } \
void NAME ## Clear() { set( #NAME, Poco::Dynamic::Var()); }

#define MAP_FIELD(NAME, TYPE) \
void NAME(const privmx::utils::Map<TYPE>& value) { set(#NAME, value); } \
privmx::utils::Map<TYPE> NAME() const { return getMap<TYPE>(#NAME); } \
privmx::utils::Map<TYPE> NAME ## Opt(const privmx::utils::Map<TYPE>& opt) { if (isNullOrUndefined(#NAME)) return opt; return NAME(); } \
bool NAME ## Empty() const { return isNullOrUndefined(#NAME); } \
void NAME ## Clear() { set( #NAME, Poco::Dynamic::Var()); }

#define MAP_VAR_FIELD(NAME) \
void NAME(const privmx::utils::Map<Poco::Dynamic::Var>& value) { set(#NAME, value); } \
privmx::utils::Map<Poco::Dynamic::Var> NAME() const { return getMap<Poco::Dynamic::Var>(#NAME); } \
privmx::utils::Map<Poco::Dynamic::Var> NAME ## Opt(const privmx::utils::Map<Poco::Dynamic::Var>& opt) { if (isNullOrUndefined(#NAME)) return opt; return NAME(); } \
bool NAME ## Empty() const { return isNullOrUndefined(#NAME); } \
void NAME ## Clear() { set( #NAME, Poco::Dynamic::Var()); }

#define LIST_FIELD(NAME, TYPE) \
void NAME(const privmx::utils::List<TYPE>& value) { set(#NAME, value); } \
privmx::utils::List<TYPE> NAME() const { return getArray<TYPE>(#NAME); } \
privmx::utils::List<TYPE> NAME ## Opt(const privmx::utils::List<TYPE>& opt) { if (isNullOrUndefined(#NAME)) return opt; return NAME(); } \
bool NAME ## Empty() const { return isNullOrUndefined(#NAME); } \
void NAME ## Clear() { set( #NAME, Poco::Dynamic::Var()); }

#define LIST_VAR_FIELD(NAME) \
void NAME(const privmx::utils::List<Poco::Dynamic::Var>& value) { set(#NAME, value); } \
privmx::utils::List<Poco::Dynamic::Var> NAME() const { return getArray<Poco::Dynamic::Var>(#NAME); } \
privmx::utils::List<Poco::Dynamic::Var> NAME ## Opt(const privmx::utils::List<Poco::Dynamic::Var>& opt) { if (isNullOrUndefined(#NAME)) return opt; return NAME(); } \
bool NAME ## Empty() const { return isNullOrUndefined(#NAME); } \
void NAME ## Clear() { set( #NAME, Poco::Dynamic::Var()); }

#define VAR_FIELD(NAME) \
void NAME(const Poco::Dynamic::Var& value) { set(#NAME, value); } \
Poco::Dynamic::Var NAME() const { return get(#NAME); } \
Poco::Dynamic::Var NAME ## Opt(const Poco::Dynamic::Var& opt) { if (isNullOrUndefined(#NAME)) return opt; return NAME(); } \
bool NAME ## Empty() const { return isNullOrUndefined(#NAME); } \
void NAME ## Clear() { set( #NAME, Poco::Dynamic::Var()); }

#define INIT_OBJECT(NAME, TYPE) \
if(isUndefined(#NAME)) { \
    initializeObject({#NAME}); \
} else if (isNull(#NAME)) { \
} else { \
    NAME().initialize(); \
}

#define INIT_MAP(NAME, TYPE) \
if(isUndefined(#NAME)) { \
    initializeObject({#NAME}); \
} else if (isNull(#NAME)) { \
} else { \
    NAME().initialize(); \
}

#define INIT_MAP_VAR(NAME, TYPE) \
if(isUndefined(#NAME)) { \
    initializeObject({#NAME}); \
}

#define INIT_LIST(NAME, TYPE) \
if(isUndefined(#NAME)) { \
    initializeObject({#NAME}); \
} else if (isNull(#NAME)) { \
} else { \
    NAME().initialize(); \
}

#define INIT_LIST_VAR(NAME) \
if(isUndefined(#NAME)) { \
    initializeObject({#NAME}); \
} 

#define INIT_VAR(NAME) \
if(isUndefined(#NAME)) { \
    initializeObject({#NAME}); \
}

#define INIT_OBJECT_PTR(NAME) \
if(isUndefined(#NAME)) { \
    Poco::JSON::Object::Ptr NAME = new Poco::JSON::Object(); \
    set(#NAME, NAME); \
}


#endif // _PRIVMXLIB_UTILS_TYPESMACROS_HPP_
