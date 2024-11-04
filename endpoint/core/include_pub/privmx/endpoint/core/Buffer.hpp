#ifndef _PRIVMXLIB_ENDPOINT_CORE_BUFFER_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_BUFFER_HPP_

#include <string>

namespace privmx {
namespace endpoint {
namespace core {

/**
 * 'Buffer' provides simple string buffer implementation.
 */
class Buffer {
public:

    /**
     * Creates Buffer from `std::string`.
     * 
     * @param str string to convert to Buffer
     * 
     * @return Buffer object
     */
    static Buffer from(const std::string& str) { return Buffer(str); }

    /**
     * Creates Buffer from `char*`.
     * 
     * @param data the char* to convert to Buffer
     * @param size data length
     * 
     * @return Buffer object
     */
    static Buffer from(const char* data, std::size_t size) { return Buffer({data, size}); }
    
    /**
     * //doc-gen:ignore
     */
    Buffer() = default;

    /**
     * Gets data as `std::string` from Buffer.
     * 
     * @return data as std::string
     */
    const std::string& stdString() const { return _data; }

    /**
     * Gets data as `std::string` from Buffer.
     * 
     * @return data as std::string
     *
     */
    std::string& stdString() { return _data; }

    /**
     * Gets Buffer data size.
     * 
     * @return data size
     *
     */
    std::size_t size() const { return _data.size(); }


    /**
     * Gets data as char* from Buffer.
     * 
     * @return data as char*
     *
     */
    const char* data() const { return _data.data(); }

private:
    Buffer(const std::string& str) : _data(str) {}

    std::string _data;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_BUFFER_HPP_
