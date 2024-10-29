#include "privmx/endpoint/store/FileDataProvider.hpp"

using namespace privmx::endpoint::store;

server::StoreFileReadResult FileDataProvider::getFileData(const server::StoreFileReadModel& model) {
    return _server->storeFileRead(model);
}
