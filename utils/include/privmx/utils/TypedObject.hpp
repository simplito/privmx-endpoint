#ifndef _PRIVMXLIB_UTILS_TYPEDOBJECT_HPP_
#define _PRIVMXLIB_UTILS_TYPEDOBJECT_HPP_

#include <utility>
#include <Poco/Dynamic/Var.h>
#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>
#include <Pson/BinaryString.hpp>

#include <privmx/utils/Utils.hpp>
#include <privmx/utils/PrivmxException.hpp>
#include <privmx/utils/PrivmxExtExceptions.hpp>

namespace privmx {
namespace utils {

class TypedObject;
class TypedObjectFactory;

template <class T>
class ListConstIteratorBase
{
public:
    ListConstIteratorBase(Poco::JSON::Array::ConstIterator it) : _it(it) {}
    bool operator!=(const ListConstIteratorBase<T> &it) {
        return it._it != _it;
    }
    virtual T operator*() = 0; /*{
            //TODO: support other types as string, Poco::Int32, Poco::Int64, Poco::JSON::Array etc..
            return T((*_it).extract<Poco::JSON::Object::Ptr>());
        }*/

protected:
    Poco::JSON::Array::ConstIterator _it;
};

template <class T = TypedObject>
class ListConstIterator : public ListConstIteratorBase<T>
{
public:
    ListConstIterator(Poco::JSON::Array::ConstIterator it) : ListConstIteratorBase<T>(it) {}
    ListConstIterator<T> operator++() {
        return this->_it++;
    }
    T operator*() override {
        const Poco::Dynamic::Var &var = *(this->_it);
        return T(var); // T((*(this->_it)).extract<Poco::JSON::Object::Ptr>())
    }
};
template <>
class ListConstIterator<Poco::JSON::Object::Ptr> : public ListConstIteratorBase<Poco::JSON::Object::Ptr>
{
public:
    ListConstIterator(Poco::JSON::Array::ConstIterator it) : ListConstIteratorBase<Poco::JSON::Object::Ptr>(it) {}
    ListConstIterator<Poco::JSON::Object::Ptr> operator++() {
        return _it++;
    }
    Poco::JSON::Object::Ptr operator*() override {
        return (*_it).extract<Poco::JSON::Object::Ptr>();
    }
};

template <>
class ListConstIterator<Poco::Dynamic::Var> : public ListConstIteratorBase<Poco::Dynamic::Var>
{
public:
    ListConstIterator(Poco::JSON::Array::ConstIterator it) : ListConstIteratorBase<Poco::Dynamic::Var>(it) {}
    ListConstIterator<Poco::Dynamic::Var> operator++() {
        return _it++;
    }
    Poco::Dynamic::Var operator*() override {
        return (*_it);
    }
};
template <>
class ListConstIterator<std::string> : public ListConstIteratorBase<std::string>
{
public:
    ListConstIterator(Poco::JSON::Array::ConstIterator it) : ListConstIteratorBase<std::string>(it) {}
    ListConstIterator<std::string> operator++() {
        return _it++;
    }
    std::string operator*() override {
        return (*_it).extract<std::string>();
    }
};
template <>
class ListConstIterator<Poco::Int32> : public ListConstIteratorBase<Poco::Int32>
{
public:
    ListConstIterator(Poco::JSON::Array::ConstIterator it) : ListConstIteratorBase<Poco::Int32>(it) {}
    ListConstIterator<Poco::Int32> operator++() {
        return _it++;
    }
    Poco::Int32 operator*() override {
        return (*_it).convert<Poco::Int32>();
    }
};
template <>
class ListConstIterator<Poco::Int64> : public ListConstIteratorBase<Poco::Int64>
{
public:
    ListConstIterator(Poco::JSON::Array::ConstIterator it) : ListConstIteratorBase<Poco::Int64>(it) {}
    ListConstIterator<Poco::Int64> operator++() {
        return _it++;
    }
    Poco::Int64 operator*() override {
        return (*_it).convert<Poco::Int64>();
    }
};
template <>
class ListConstIterator<double> : public ListConstIteratorBase<double>
{
public:
    ListConstIterator(Poco::JSON::Array::ConstIterator it) : ListConstIteratorBase<double>(it) {}
    ListConstIterator<double> operator++() {
        return _it++;
    }
    double operator*() override {
        return (*_it).extract<double>();
    }
};
template <>
class ListConstIterator<Pson::BinaryString> : public ListConstIteratorBase<Pson::BinaryString>
{
public:
    ListConstIterator(Poco::JSON::Array::ConstIterator it) : ListConstIteratorBase<Pson::BinaryString>(it) {}
    ListConstIterator<Pson::BinaryString> operator++() {
        return _it++;
    }
    Pson::BinaryString operator*() override {
        return (*_it).extract<Pson::BinaryString>();
    }
};
template <>
class ListConstIterator<bool> : public ListConstIteratorBase<bool>
{
public:
    ListConstIterator(Poco::JSON::Array::ConstIterator it) : ListConstIteratorBase<bool>(it) {}
    ListConstIterator<bool> operator++() {
        return _it++;
    }
    bool operator*() override {
        return (*_it).extract<bool>();
    }
};

template <class T>
class ListBase
{
public:
    ListBase() {}
    ListBase( const Poco::Dynamic::Var &arr) : _arr(arr.extract<Poco::JSON::Array::Ptr>()) {}
    ListBase(const Poco::JSON::Array::Ptr &arr) : _arr(arr) {}
    operator Poco::Dynamic::Var() const {
        return Poco::Dynamic::Var(_arr);
    }
    operator Poco::JSON::Array::Ptr() const {
        return _arr;
    }
    virtual T get(unsigned int index) const = 0; /* {
            return _arr->get(index);
        }*/
    bool has(const T &obj) {
        for(auto a : *_arr) {
            if(a == obj) {
                return true;
            }
        }
        return false;
    }
    void remove(unsigned int index) {
        _arr->remove(index);
    }
    void add(const T &obj) {
        _arr->add(obj);
    }
    ListConstIterator<T> begin() const {
        return _arr->begin();
    }
    ListConstIterator<T> end() const {
        return _arr->end();
    }
    virtual void initialize(){};
    std::size_t size() const {
        return _arr->size();
    }
    bool isNull() const {
        return _arr.isNull();
    }


protected:
    Poco::JSON::Array::Ptr _arr;
};

template <class T>
class List : public ListBase<T>
{
public:
    List() {}
    List(const Poco::Dynamic::Var &arr) : ListBase<T>(arr) {}
    List(const Poco::JSON::Array::Ptr &arr) : ListBase<T>(arr) {}
    T get(unsigned int index) const override {
        Poco::Dynamic::Var var = this->_arr->get(index);
        return T(var);
    }
    
    void initialize() override {
        for (auto item : *this) {
            item.initialize();
        }
    }
    List<T> copy() {
        return List(privmx::utils::Utils::jsonArrayDeepCopy(this->_arr));
    }
};
template <>
class List<Poco::JSON::Object::Ptr> : public ListBase<Poco::JSON::Object::Ptr>
{
public:
    List() {}
    List(const Poco::Dynamic::Var &arr) : ListBase<Poco::JSON::Object::Ptr>(arr) {}
    List(const Poco::JSON::Array::Ptr &arr) : ListBase<Poco::JSON::Object::Ptr>(arr) {}
    Poco::JSON::Object::Ptr get(unsigned int index) const override {
        return _arr->getObject(index);
    }
    void initialize() override {}
    List<Poco::JSON::Object::Ptr> copy() {
        return List(privmx::utils::Utils::jsonArrayDeepCopy(this->_arr));
    }
};

template <>
class List<Poco::Dynamic::Var> : public ListBase<Poco::Dynamic::Var>
{
public:
    List() {}
    List(const Poco::Dynamic::Var &arr) : ListBase<Poco::Dynamic::Var>(arr) {}
    List(const Poco::JSON::Array::Ptr &arr) : ListBase<Poco::Dynamic::Var>(arr) {}
    Poco::Dynamic::Var get(unsigned int index) const override {
        return _arr->get(index);
    }
    void initialize() override {}
    List<Poco::Dynamic::Var> copy() {
        return List(privmx::utils::Utils::jsonArrayDeepCopy(this->_arr));
    }
};
template <>
class List<std::string> : public ListBase<std::string>
{
public:
    List() {}
    List(const Poco::Dynamic::Var &arr) : ListBase<std::string>(arr) {}
    List(const Poco::JSON::Array::Ptr &arr) : ListBase<std::string>(arr) {}
    std::string get(unsigned int index) const override {
        return _arr->get(index).extract<std::string>();
    }
    void initialize() override {}
    List<std::string> copy() {
        return List(privmx::utils::Utils::jsonArrayDeepCopy(this->_arr));
    }
};
template <>
class List<Poco::Int32> : public ListBase<Poco::Int32>
{
public:
    List() {}
    List(const Poco::Dynamic::Var &arr) : ListBase<Poco::Int32>(arr) {}
    List(const Poco::JSON::Array::Ptr &arr) : ListBase<Poco::Int32>(arr) {}
    Poco::Int32 get(unsigned int index) const override {
        return _arr->get(index).convert<Poco::Int32>();
    }
    List<Poco::Int32> copy() {
        return List(privmx::utils::Utils::jsonArrayDeepCopy(this->_arr));
    }
};
template <>
class List<Poco::Int64> : public ListBase<Poco::Int64>
{
public:
    List() {}
    List(const Poco::Dynamic::Var &arr) : ListBase<Poco::Int64>(arr) {}
    List(const Poco::JSON::Array::Ptr &arr) : ListBase<Poco::Int64>(arr) {}
    Poco::Int64 get(unsigned int index) const override {
        return _arr->get(index).convert<Poco::Int64>();
    }
    List<Poco::Int64> copy() {
        return List(privmx::utils::Utils::jsonArrayDeepCopy(this->_arr));
    }
};
template <>
class List<double> : public ListBase<double>
{
public:
    List() {}
    List(const Poco::Dynamic::Var &arr) : ListBase<double>(arr) {}
    List(const Poco::JSON::Array::Ptr &arr) : ListBase<double>(arr) {}
    double get(unsigned int index) const {
        return _arr->get(index).extract<double>();
    }
    List<double> copy() {
        return List(privmx::utils::Utils::jsonArrayDeepCopy(this->_arr));
    }
};
template <>
class List<Pson::BinaryString> : public ListBase<Pson::BinaryString>
{
public:
    List() {}
    List(const Poco::Dynamic::Var &arr) : ListBase<Pson::BinaryString>(arr) {}
    List(const Poco::JSON::Array::Ptr &arr) : ListBase<Pson::BinaryString>(arr) {}
    Pson::BinaryString get(unsigned int index) const {
        return _arr->get(index).extract<Pson::BinaryString>();
    }
    List<Pson::BinaryString> copy() {
        return List(privmx::utils::Utils::jsonArrayDeepCopy(this->_arr));
    }
};
template <>
class List<bool> : public ListBase<bool>
{
public:
    List() {}
    List(const Poco::Dynamic::Var &arr) : ListBase<bool>(arr) {}
    List(const Poco::JSON::Array::Ptr &arr) : ListBase<bool>(arr) {}
    bool get(unsigned int index) const {
        return _arr->get(index).extract<bool>();
    }
    List<bool> copy() {
        return List(privmx::utils::Utils::jsonArrayDeepCopy(this->_arr));
    }
};

template <class T>
class MapConstIteratorBase
{
public:
    MapConstIteratorBase(Poco::JSON::Object::ConstIterator it) : _it(it) {}
    bool operator!=(const MapConstIteratorBase &it) {
        return it._it != _it;
    }
    virtual std::pair<std::string, T> operator*() = 0; /*{
            //TODO: support other types as string, Poco::Int32, Poco::Int64, Poco::JSON::Array etc..
            return T((*_it).extract<Poco::JSON::Object::Ptr>());
        }*/

protected:
    Poco::JSON::Object::ConstIterator _it;
};

template <class T = TypedObject>
class MapConstIterator : public MapConstIteratorBase<T>
{
public:
    MapConstIterator(Poco::JSON::Object::ConstIterator it) : MapConstIteratorBase<T>(it) {}
    MapConstIterator<T> operator++() {
        return this->_it++;
    }
    std::pair<std::string, T> operator*() override {
        const std::string &key = (*this->_it).first;
        const Poco::Dynamic::Var &var = (*this->_it).second;
        return {key, T(var)}; // T((*(this->_it)).extract<Poco::JSON::Object::Ptr>())
    }
};
template <>
class MapConstIterator<Poco::JSON::Object::Ptr> : public MapConstIteratorBase<Poco::JSON::Object::Ptr>
{
public:
    MapConstIterator(Poco::JSON::Object::ConstIterator it) : MapConstIteratorBase<Poco::JSON::Object::Ptr>(it) {}
    MapConstIterator<Poco::JSON::Object::Ptr> operator++() {
        return this->_it++;
    }
    std::pair<std::string, Poco::JSON::Object::Ptr> operator*() override {
        return {(*this->_it).first, (*_it).second.extract<Poco::JSON::Object::Ptr>()};
    }
};

template <>
class MapConstIterator<Poco::Dynamic::Var> : public MapConstIteratorBase<Poco::Dynamic::Var>
{
public:
    MapConstIterator(Poco::JSON::Object::ConstIterator it) : MapConstIteratorBase<Poco::Dynamic::Var>(it) {}
    MapConstIterator<Poco::Dynamic::Var> operator++() {
        return this->_it++;
    }
    std::pair<std::string, Poco::Dynamic::Var> operator*() override {
        return {(*this->_it).first, (*_it).second};
    }
};

template <>
class MapConstIterator<std::string> : public MapConstIteratorBase<std::string>
{
public:
    MapConstIterator(Poco::JSON::Object::ConstIterator it) : MapConstIteratorBase<std::string>(it) {}
    MapConstIterator<std::string> operator++() {
        return this->_it++;
    }
    std::pair<std::string, std::string> operator*() override {
        return {(*this->_it).first, (*_it).second.extract<std::string>()};
    }
};
template <>
class MapConstIterator<Poco::Int32> : public MapConstIteratorBase<Poco::Int32>
{
public:
    MapConstIterator(Poco::JSON::Object::ConstIterator it) : MapConstIteratorBase<Poco::Int32>(it) {}
    MapConstIterator<Poco::Int32> operator++() {
        return this->_it++;
    }
    std::pair<std::string, Poco::Int32> operator*() override {
        return {(*this->_it).first, (*_it).second.convert<Poco::Int32>()};
    }
};
template <>
class MapConstIterator<Poco::Int64> : public MapConstIteratorBase<Poco::Int64>
{
public:
    MapConstIterator(Poco::JSON::Object::ConstIterator it) : MapConstIteratorBase<Poco::Int64>(it) {}
    MapConstIterator<Poco::Int64> operator++() {
        return this->_it++;
    }
    std::pair<std::string, Poco::Int64> operator*() override {
        return {(*this->_it).first, (*_it).second.convert<Poco::Int64>()};
    }
};
template <>
class MapConstIterator<double> : public MapConstIteratorBase<double>
{
public:
    MapConstIterator(Poco::JSON::Object::ConstIterator it) : MapConstIteratorBase<double>(it) {}
    MapConstIterator<double> operator++() {
        return this->_it++;
    }
    std::pair<std::string, double> operator*() override {
        return {(*this->_it).first, (*_it).second.extract<double>()};
    }
};
template <>
class MapConstIterator<Pson::BinaryString> : public MapConstIteratorBase<Pson::BinaryString>
{
public:
    MapConstIterator(Poco::JSON::Object::ConstIterator it) : MapConstIteratorBase<Pson::BinaryString>(it) {}
    MapConstIterator<Pson::BinaryString> operator++() {
        return this->_it++;
    }
    std::pair<std::string, Pson::BinaryString> operator*() override {
        return {(*this->_it).first, (*_it).second.extract<Pson::BinaryString>()};
    }
};
template <>
class MapConstIterator<bool> : public MapConstIteratorBase<bool>
{
public:
    MapConstIterator(Poco::JSON::Object::ConstIterator it) : MapConstIteratorBase<bool>(it) {}
    MapConstIterator<bool> operator++() {
        return this->_it++;
    }
    std::pair<std::string, bool> operator*() override {
        return {(*this->_it).first, (*_it).second.extract<bool>()};
    }
};

template <class T = TypedObject>
class MapBase
{
public:
    MapBase() {}
    MapBase(const Poco::Dynamic::Var &map) : _map(map.extract<Poco::JSON::Object::Ptr>()) {}
    MapBase(const Poco::JSON::Object::Ptr &map) : _map(map) {}
    operator Poco::Dynamic::Var() const {
        return Poco::Dynamic::Var(_map);
    }
    operator Poco::JSON::Object::Ptr() const {
        return _map;
    }
    virtual T get(const std::string &key) const = 0; /*{
        return T(this->getInit(key).extract<Poco::JSON::Object::Ptr>());
    }*/

    void add(const std::string &key, const T &value) {
        _map->set(key, value);
    }
    void remove(const std::string &key) {
        _map->remove(key);
    }
    MapConstIterator<T> begin() const {
        return this->_map->begin();
    }
    MapConstIterator<T> end() const {
        return this->_map->end();
    }
    bool hasKey(const std::string &key) const {
        return this->_map->has(key);
    }
    bool isNull() const {
        return _map.isNull();
    }

    List<std::string> getKeys() {
        List<std::string> res(static_cast<Poco::JSON::Array::Ptr>(new Poco::JSON::Array()));
        res.initialize();
        for(auto a = this->_map->begin(); a != this->_map->end(); a++) {
            res.add( a->first );
        }
        return res;
    }
    virtual void initialize() {} /*{
        for(Poco::JSON::Object::Iterator it = _map->begin(); _map->end() != it; it++) {
            get(it->first).initialize();
        }
    }*/
    // działatyko na obiekty
protected:
    Poco::Dynamic::Var getInit(const std::string &key) const {
        if (!_map->has(key)) {
            throw KeyNotExistException();
        }
        return _map->get(key);
    }
    
    Poco::JSON::Object::Ptr _map;
};

template <class T>
class Map : public MapBase<T>
{
public:
    Map() {}
    Map(const Poco::Dynamic::Var &map) : MapBase<T>(map) {}
    Map(const Poco::JSON::Object::Ptr &map) : MapBase<T>(map) {}
    T get(const std::string &key) const override {
        Poco::Dynamic::Var var = this->getInit(key);
        return T(var);
    }
    void initialize() override {
        for (Poco::JSON::Object::Iterator it = this->_map->begin(); this->_map->end() != it; it++) {
            get(it->first).initialize();
        }
    }
    Map<T> copy() {
        return Map(privmx::utils::Utils::jsonObjectDeepCopy(this->_map));
    }
};

template <>
class Map<Poco::JSON::Object::Ptr> : public MapBase<Poco::JSON::Object::Ptr>
{
public:
    Map() {}
    Map(const Poco::Dynamic::Var &map) : MapBase<Poco::JSON::Object::Ptr>(map) {}
    Map(const Poco::JSON::Object::Ptr &map) : MapBase<Poco::JSON::Object::Ptr>(map) {}
    void initialize() override {}
    Poco::JSON::Object::Ptr get(const std::string &key) const override {
        return this->getInit(key).extract<Poco::JSON::Object::Ptr>();
    }
    Map<Poco::JSON::Object::Ptr> copy() {
        return Map(privmx::utils::Utils::jsonObjectDeepCopy(this->_map));
    }
};

template <>
class Map<Poco::Dynamic::Var> : public MapBase<Poco::Dynamic::Var>
{
public:
    Map() {}
    Map(const Poco::Dynamic::Var &map) : MapBase<Poco::Dynamic::Var>(map) {}
    Map(const Poco::JSON::Object::Ptr &map) : MapBase<Poco::Dynamic::Var>(map) {}
    void initialize() override {}
    Poco::Dynamic::Var get(const std::string &key) const override {
        return this->getInit(key);
    }
    Map<Poco::Dynamic::Var> copy() {
        return Map(privmx::utils::Utils::jsonObjectDeepCopy(this->_map));
    }
};
template <>
class Map<std::string> : public MapBase<std::string>
{
public:
    Map() {}
    Map(const Poco::Dynamic::Var &map) : MapBase<std::string>(map) {}
    Map(const Poco::JSON::Object::Ptr &map) : MapBase<std::string>(map) {}
    void initialize() override {}
    std::string get(const std::string &key) const override {
        return this->getInit(key).extract<std::string>();
    }
    Map<std::string> copy() {
        return Map(privmx::utils::Utils::jsonObjectDeepCopy(this->_map));
    }
};


template <>
class Map<Poco::Int32> : public MapBase<Poco::Int32>
{
public:
    Map() {}
    Map(const Poco::Dynamic::Var &map) : MapBase<Poco::Int32>(map) {}
    Map(const Poco::JSON::Object::Ptr &map) : MapBase<Poco::Int32>(map) {}
    void initialize() override {}
    Poco::Int32 get(const std::string &key) const override {
        return this->getInit(key).convert<Poco::Int32>();
    }
    Map<Poco::Int32> copy() {
        return Map(privmx::utils::Utils::jsonObjectDeepCopy(this->_map));
    }
};
template <>
class Map<Poco::Int64> : public MapBase<Poco::Int64>
{
public:
    Map() {}
    Map(const Poco::Dynamic::Var &map) : MapBase<Poco::Int64>(map) {}
    Map(const Poco::JSON::Object::Ptr &map) : MapBase<Poco::Int64>(map) {}
    void initialize() override {}
    Poco::Int64 get(const std::string &key) const override {
        return this->getInit(key).convert<Poco::Int64>();
    }
    Map<Poco::Int64> copy() {
        return Map(privmx::utils::Utils::jsonObjectDeepCopy(this->_map));
    }
};
template <>
class Map<double> : public MapBase<double>
{
public:
    Map() {}
    Map(const Poco::Dynamic::Var &map) : MapBase<double>(map) {}
    Map(const Poco::JSON::Object::Ptr &map) : MapBase<double>(map) {}
    void initialize() override {}
    double get(const std::string &key) const override {
        return this->getInit(key).extract<double>();
    }
    Map<double> copy() {
        return Map(privmx::utils::Utils::jsonObjectDeepCopy(this->_map));
    }
};
template <>
class Map<Pson::BinaryString> : public MapBase<Pson::BinaryString>
{
public:
    Map() {}
    Map(const Poco::Dynamic::Var &map) : MapBase<Pson::BinaryString>(map) {}
    Map(const Poco::JSON::Object::Ptr &map) : MapBase<Pson::BinaryString>(map) {}
    void initialize() override {}
    Pson::BinaryString get(const std::string &key) const override {
        return this->getInit(key).extract<Pson::BinaryString>();
    }
    Map<Pson::BinaryString> copy() {
        return Map(privmx::utils::Utils::jsonObjectDeepCopy(this->_map));
    }
};
template <>
class Map<bool> : public MapBase<bool>
{
public:
    Map() {}
    Map(const Poco::Dynamic::Var &map) : MapBase<bool>(map) {}
    Map(const Poco::JSON::Object::Ptr &map) : MapBase<bool>(map) {}
    void initialize() override {}
    bool get(const std::string &key) const override {
        return this->getInit(key).extract<bool>();
    }
    Map<bool> copy() {
        return Map(privmx::utils::Utils::jsonObjectDeepCopy(this->_map));
    }
};

class TypedObject
{
public:
    virtual ~TypedObject() = default;
    operator Poco::Dynamic::Var() const {
        return Poco::Dynamic::Var(_obj);
    }
    operator Poco::JSON::Object::Ptr() const {
        return _obj;
    }
    friend bool operator==(const TypedObject& t1, const TypedObject& t2) {
        return ((Poco::Dynamic::Var)t1._obj) == ((Poco::Dynamic::Var)t2._obj);
    }
    bool isNull() const {
        return _obj.isNull();
    }
    Poco::Dynamic::Var asVar() const {
        return Poco::Dynamic::Var(_obj);
    }
    Poco::JSON::Object::Ptr asObject() const {
        return _obj;
    }
    std::string toString() const {
        return asVar().toString();
    }
    
    void print() const {
        _obj->stringify(std::cerr, 2, 2);
    }

protected:
    TypedObject() {}
    TypedObject(const Poco::Dynamic::Var &obj, bool add_nulls = false, bool add_type = false, const std::string &type = std::string())
        : _obj(obj.extract<Poco::JSON::Object::Ptr>()), _add_nulls(add_nulls), _add_type(add_type), _type(type) {}
    TypedObject(const Poco::JSON::Object::Ptr &obj, bool add_nulls = false, bool add_type = false, const std::string &type = std::string())
        : _obj(obj), _add_nulls(add_nulls), _add_type(add_type), _type(type) {}
    virtual void initialize() = 0;
    void initializeObject(const std::vector<std::string> &keys) {
        // TODO: recursive initialize objects
        if (_add_type && (!_obj->has("__type") || _obj->get("__type") != _type)) {
            _obj->set("__type", _type);
        }
        if (!_add_nulls)
            return;
        for (const auto &key : keys) {
            if (isUndefined(key))
            {
                set(key, Poco::Dynamic::Var());
            }
        }
    }
    void set(const std::string &key, const Poco::Dynamic::Var &value) {
        _obj->set(key, value);
    }
    Poco::Dynamic::Var get(const std::string &key) const {
        return _obj->get(key);
    }
    bool isUndefined(const std::string &key) const {
        return !_obj->has(key);
    }
    bool isNull(const std::string &key) const {
        return _obj->get(key).isEmpty();
    }
    bool isNullOrUndefined(const std::string &key) const {
        return (isUndefined(key) || isNull(key));
    }
    template <class X, class T = List<X>>
    T getArray(const std::string &key) const {
        return T(_obj->getArray(key));
    }
    template <class X, class T = Map<X>>
    T getMap(const std::string &key) const {
        return T(_obj->getObject(key));
    }
    template <class T = TypedObject>
    T getObject(const std::string &key) const {
        return T(_obj->getObject(key));
    }
    Poco::JSON::Object::Ptr copyObject() {
        return privmx::utils::Utils::jsonObjectDeepCopy(_obj);
    }
private:
    Poco::JSON::Object::Ptr _obj = nullptr;
    bool _add_nulls = false;
    bool _add_type = false;
    std::string _type = std::string();
};

class TypedObjectFactory
{
public:
    template <class T = TypedObject>
    static T createObjectFromVar(const Poco::Dynamic::Var &var) {
        if (var.type() != typeid(Poco::JSON::Object::Ptr)) {
            throw VarIsNotObjectException();
        }
        T res(var);
        res.initialize();
        return res;
    }
    template <class T = TypedObject>
    static T createNewObject() {
        T res(Poco::JSON::Object::Ptr(new Poco::JSON::Object()));
        res.initialize();
        return res;
    }

    template <class T = TypedObject>
    static List<T> createListFromVar(const Poco::Dynamic::Var &var) {
        if (var.type() != typeid(Poco::JSON::Array::Ptr)) {
            throw VarIsNotArrayException();
        }
        List<T> res(var.extract<Poco::JSON::Array::Ptr>());
        res.initialize();
        return res;
    }
    template <class T>
    static List<T> createNewList() {
        List<T> res(Poco::JSON::Array::Ptr(new Poco::JSON::Array()));
        res.initialize();
        return res;
    }
    template <class T = TypedObject>
    static Map<T> createMapFromVar(const Poco::Dynamic::Var &var) {
        if (var.type() != typeid(Poco::JSON::Object::Ptr)) {
            throw VarIsNotObjectException();
        }
        Map<T> res(var.extract<Poco::JSON::Object::Ptr>());
        res.initialize();
        return res;
    }
    template <class T = TypedObject>
    static Map<T> createNewMap() {
        Map<T> res(Poco::JSON::Object::Ptr(new Poco::JSON::Object()));
        res.initialize();
        return res;
    }
};

} // utils
} // privmx

#endif // _PRIVMXLIB_UTILS_TYPEDOBJECT_HPP_
