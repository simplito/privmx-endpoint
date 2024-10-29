#ifndef _PRIVMXLIB_ENDPOINT_STORE_FILEREADER_INTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_FILEREADER_INTERFACE_HPP_

namespace privmx {
namespace endpoint {
namespace store {

class IFileReader
{
public:
    virtual ~IFileReader() = default;
    virtual std::string read(uint64_t pos, size_t length) = 0;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_FILEREADER_INTERFACE_HPP_