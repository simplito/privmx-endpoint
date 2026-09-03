/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "privmx/endpoint/core/Connection.hpp"
#include "privmx/endpoint/core/Exception.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/kvdb/KvdbApi.hpp"
#include "privmx/endpoint/search/Types.hpp"
#include "privmx/endpoint/store/StoreApi.hpp"

#include <sqlite3.h>

#include <exception>
#include <iostream>
#include <stdexcept>
#include <unistd.h>

#include "privmx/endpoint/search/PrivmxFS.hpp"

#include "privmx/endpoint/search/PrivmxSqliteVFS.hpp"

#include <privmx/utils/Logger.hpp>

using namespace privmx::endpoint::search;

extern "C" {

struct privmx_file {
    sqlite3_file base;
    void* pmxFile;
};
typedef privmx_file privmx_file;
}

inline std::shared_ptr<PrivmxFile> extractPrivmxFile(sqlite3_file* pFile) {
    privmx_file* file = (privmx_file*)pFile;
    if (file->pmxFile != nullptr) {
        return *((std::shared_ptr<PrivmxFile>*)((privmx_file*)pFile)->pmxFile);
    }
    return std::shared_ptr<PrivmxFile>();
}

inline std::shared_ptr<PrivmxExtFS> extractPrivmxExtFS(sqlite3_vfs* pVfs) {
    return *((std::shared_ptr<PrivmxExtFS>*)(pVfs->pAppData));
}

inline void freePrivmxFile(sqlite3_file* pFile) {
    privmx_file* file = (privmx_file*)pFile;
    if (file->pmxFile != nullptr) {
        delete (std::shared_ptr<PrivmxFile>*)((privmx_file*)pFile)->pmxFile;
    }
}

extern "C" {

int privmxClose(sqlite3_file* pFile) {
    std::shared_ptr<PrivmxFile> file = extractPrivmxFile(pFile);
    try {
        if (file) {
            file->close();
            freePrivmxFile(pFile);
        }
    } catch (const privmx::endpoint::core::Exception& e) {
        LOG_ERROR("privmxClose - ", e.getFull())
        return SQLITE_IOERR;
    } catch (const std::exception& e) {
        LOG_ERROR("privmxClose - ", e.what())
        return SQLITE_IOERR;
    } catch (...) {
        LOG_ERROR("privmxClose - unknown exception")
        return SQLITE_IOERR;
    }
    return SQLITE_OK;
}

int privmxRead(sqlite3_file* pFile, void* zBuf, int iAmt, sqlite3_int64 iOfst) {
    std::shared_ptr<PrivmxFile> file = extractPrivmxFile(pFile);
    try {
        std::size_t expectedSize = static_cast<std::size_t>(iAmt);
        auto data = file->read(iAmt, iOfst);
        if (data.size() > expectedSize) {
            return SQLITE_IOERR_READ;
        }
        std::memcpy(zBuf, data.data(), data.size());
        if (data.size() < expectedSize) {
            std::memset(static_cast<char*>(zBuf) + data.size(), 0, expectedSize - data.size());
            return SQLITE_IOERR_SHORT_READ;
        }
    } catch (const privmx::endpoint::core::Exception& e) {
        LOG_ERROR("privmxRead - ", e.getFull())
        std::memset(zBuf, 0, iAmt);
        return SQLITE_IOERR_READ;
    } catch (const std::exception& e) {
        LOG_ERROR("privmxRead - ", e.what())
        std::memset(zBuf, 0, iAmt);
        return SQLITE_IOERR_READ;
    } catch (...) {
        LOG_ERROR("privmxRead - unknown exception")
        std::memset(zBuf, 0, iAmt);
        return SQLITE_IOERR_READ;
    }
    return SQLITE_OK;
}

int privmxWrite(sqlite3_file* pFile, const void* zBuf, int iAmt, sqlite3_int64 iOfst) {
    std::shared_ptr<PrivmxFile> file = extractPrivmxFile(pFile);
    try {
        file->write(privmx::endpoint::core::Buffer::from((char*)zBuf, iAmt), iOfst);
    } catch (const privmx::endpoint::core::Exception& e) {
        LOG_ERROR("privmxWrite - ", e.getFull())
        return SQLITE_IOERR_WRITE;
    } catch (const std::exception& e) {
        LOG_ERROR("privmxWrite - ", e.what())
        return SQLITE_IOERR_WRITE;
    } catch (...) {
        LOG_ERROR("privmxWrite - unknown exception")
        return SQLITE_IOERR_WRITE;
    }
    return SQLITE_OK;
}

int privmxTruncate(sqlite3_file* pFile, sqlite3_int64 size) {
    std::shared_ptr<PrivmxFile> file = extractPrivmxFile(pFile);
    try {
        file->truncate(size);
    } catch (const privmx::endpoint::core::Exception& e) {
        LOG_ERROR("privmxTruncate - ", e.getFull())
        return SQLITE_IOERR;
    } catch (const std::exception& e) {
        LOG_ERROR("privmxTruncate - ", e.what())
        return SQLITE_IOERR;
    } catch (...) {
        LOG_ERROR("privmxTruncate - unknown exception")
        return SQLITE_IOERR;
    }
    return SQLITE_OK;
}

int privmxSync(sqlite3_file* pFile, int /*flags*/) {
    std::shared_ptr<PrivmxFile> file = extractPrivmxFile(pFile);
    try {
        file->sync();
    } catch (const privmx::endpoint::core::Exception& e) {
        LOG_ERROR("privmxSync - ", e.getFull())
        return SQLITE_IOERR;
    } catch (const std::exception& e) {
        LOG_ERROR("privmxSync - ", e.what())
        return SQLITE_IOERR;
    } catch (...) {
        LOG_ERROR("privmxSync - unknown exception")
        return SQLITE_IOERR;
    }
    return SQLITE_OK;
}

int privmxFileSize(sqlite3_file* pFile, sqlite3_int64* pSize) {
    std::shared_ptr<PrivmxFile> file = extractPrivmxFile(pFile);
    try {
        *pSize = file->getFileSize();
    } catch (const privmx::endpoint::core::Exception& e) {
        LOG_ERROR("privmxFileSize - ", e.getFull())
        return SQLITE_IOERR;
    } catch (const std::exception& e) {
        LOG_ERROR("privmxFileSize - ", e.what())
        return SQLITE_IOERR;
    } catch (...) {
        LOG_ERROR("privmxFileSize - unknown exception")
        return SQLITE_IOERR;
    }
    return SQLITE_OK;
}

int privmxLock(sqlite3_file* pFile, int eLock) {
    std::shared_ptr<PrivmxFile> file = extractPrivmxFile(pFile);
    try {
        if (file->lock((privmx::endpoint::search::LockLevel)eLock)) {
            return SQLITE_OK;
        } else {
            return SQLITE_BUSY;
        }
    } catch (const privmx::endpoint::core::Exception& e) {
        LOG_ERROR("privmxLock - ", e.getFull())
        return SQLITE_IOERR;
    } catch (const std::exception& e) {
        LOG_ERROR("privmxLock - ", e.what())
        return SQLITE_IOERR;
    } catch (...) {
        LOG_ERROR("privmxLock - unknown exception")
        return SQLITE_IOERR;
    }
}

int privmxUnlock(sqlite3_file* pFile, int eLock) {
    std::shared_ptr<PrivmxFile> file = extractPrivmxFile(pFile);
    try {
        if (file->unlock((privmx::endpoint::search::LockLevel)eLock)) {
            return SQLITE_OK;
        } else {
            return SQLITE_IOERR;
        }
    } catch (const privmx::endpoint::core::Exception& e) {
        LOG_ERROR("privmxUnlock - ", e.getFull())
        return SQLITE_IOERR;
    } catch (const std::exception& e) {
        LOG_ERROR("privmxUnlock - ", e.what())
        return SQLITE_IOERR;
    } catch (...) {
        LOG_ERROR("privmxUnlock - unknown exception")
        return SQLITE_IOERR;
    }
}

int privmxCheckReservedLock(sqlite3_file* pFile, int* pResOut) {
    std::shared_ptr<PrivmxFile> file = extractPrivmxFile(pFile);
    *pResOut = 0;
    try {
        *pResOut = file->checkReservedLock();
        return SQLITE_OK;
    } catch (const privmx::endpoint::core::Exception& e) {
        LOG_ERROR("privmxCheckReservedLock - ", e.getFull())
        return SQLITE_IOERR;
    } catch (const std::exception& e) {
        LOG_ERROR("privmxCheckReservedLock - ", e.what())
        return SQLITE_IOERR;
    } catch (...) {
        LOG_ERROR("privmxCheckReservedLock - unknown exception")
        return SQLITE_IOERR;
    }
}

int privmxFileControl(sqlite3_file* /*pFile*/, int /*op*/, void* /*pArg*/) {
    return SQLITE_NOTFOUND;
}

int privmxSectorSize(sqlite3_file* /*pFile*/) {
    return 512;
}

int privmxDeviceCharacteristics(sqlite3_file* /*pFile*/) {
    return 0;
}

const sqlite3_io_methods PrivmxIoMethods = {
    1,
    privmxClose,
    privmxRead,
    privmxWrite,
    privmxTruncate,
    privmxSync,
    privmxFileSize,
    privmxLock,
    privmxUnlock,
    privmxCheckReservedLock,
    privmxFileControl,
    privmxSectorSize,
    privmxDeviceCharacteristics,
    nullptr, // xShmMap    (version 2+)
    nullptr, // xShmLock   (version 2+)
    nullptr, // xShmBarrier(version 2+)
    nullptr, // xShmUnmap  (version 2+)
    nullptr, // xFetch     (version 3+)
    nullptr, // xUnfetch   (version 3+)
};

int privmxOpen(sqlite3_vfs* pVfs, const char* zName, sqlite3_file* pFile, int flags, int* pOutFlags) {
    privmx_file* file = (privmx_file*)pFile;
    std::memset(file, 0, sizeof(privmx_file));
    file->base.pMethods = &PrivmxIoMethods;
    if (pOutFlags)
        *pOutFlags = flags;
    std::shared_ptr<PrivmxExtFS> fs = extractPrivmxExtFS(pVfs);
    try {
        file->pmxFile = new std::shared_ptr<PrivmxFile>(fs->openFile(zName));
    } catch (const privmx::endpoint::core::Exception& e) {
        LOG_ERROR("privmxOpen - ", zName, " - ", e.getFull())
        return SQLITE_IOERR;
    } catch (const std::exception& e) {
        LOG_ERROR("privmxOpen - ", zName, " - ", e.what())
        return SQLITE_IOERR;
    } catch (...) {
        LOG_ERROR("privmxOpen - ", zName, " - unknown exception")
        return SQLITE_IOERR;
    }
    return SQLITE_OK;
}

int privmxDelete(sqlite3_vfs* pVfs, const char* zName, int /*syncDir*/) {
    std::shared_ptr<PrivmxExtFS> fs = extractPrivmxExtFS(pVfs);
    try {
        fs->deleteFile(zName);
    } catch (const privmx::endpoint::core::Exception& e) {
        LOG_ERROR("privmxDelete - ", zName, " - ", e.getFull())
        return SQLITE_IOERR;
    } catch (const std::exception& e) {
        LOG_ERROR("privmxDelete - ", zName, " - ", e.what())
        return SQLITE_IOERR;
    } catch (...) {
        LOG_ERROR("privmxDelete - ", zName, " - unknown exception")
        return SQLITE_IOERR;
    }
    return SQLITE_OK;
}

int privmxAccess(sqlite3_vfs* pVfs, const char* zName, int /*flags*/, int* pResOut) {
    std::shared_ptr<PrivmxExtFS> fs = extractPrivmxExtFS(pVfs);
    try {
        *pResOut = fs->access(zName);
    } catch (const privmx::endpoint::core::Exception& e) {
        LOG_ERROR("privmxAccess - ", zName, " - ", e.getFull())
        return SQLITE_IOERR;
    } catch (const std::exception& e) {
        LOG_ERROR("privmxAccess - ", zName, " - ", e.what())
        return SQLITE_IOERR;
    } catch (...) {
        LOG_ERROR("privmxAccess - ", zName, " - unknown exception")
        return SQLITE_IOERR;
    }
    return SQLITE_OK;
}

int privmxFullPathname(sqlite3_vfs* pVfs, const char* zName, int nOut, char* zOut) {
    std::shared_ptr<PrivmxExtFS> fs = extractPrivmxExtFS(pVfs);
    try {
        sqlite3_snprintf(nOut, zOut, "%s", fs->fullPathname(zName).c_str());
    } catch (const privmx::endpoint::core::Exception& e) {
        LOG_ERROR("privmxFullPathname - ", zName, " - ", e.getFull())
        return SQLITE_IOERR;
    } catch (const std::exception& e) {
        LOG_ERROR("privmxFullPathname - ", zName, " - ", e.what())
        return SQLITE_IOERR;
    } catch (...) {
        LOG_ERROR("privmxFullPathname - ", zName, " - unknown exception")
        return SQLITE_IOERR;
    }
    return SQLITE_OK;
}

void* privmxDlOpen(sqlite3_vfs* /*pVfs*/, const char* /*zFilename*/) {
    return nullptr;
}

void privmxDlError(sqlite3_vfs* /*pVfs*/, int /*nByte*/, char* /*zErrMsg*/) {}

void (*privmxDlSym(sqlite3_vfs* /*pVfs*/, void* /*p*/, const char* /*zSymbol*/))(void) {
    return nullptr;
}

void privmxDlClose(sqlite3_vfs* /*pVfs*/, void* /*p*/) {}

int privmxRandomness(sqlite3_vfs* /*pVfs*/, int nByte, char* zOut) {
    memset(zOut, 0, nByte);
    return SQLITE_OK;
}

int privmxSleep(sqlite3_vfs* /*pVfs*/, int microseconds) {
    sleep(microseconds / 1000000);
    usleep(microseconds % 1000000);
    return microseconds;
}

int privmxCurrentTime(sqlite3_vfs* /*pVfs*/, double* pTime) {
    time_t t = time(0);
    *pTime = t / 86400.0 + 2440587.5;
    return SQLITE_OK;
}

sqlite3_vfs* sqlite3_privmxvfs() {
    static sqlite3_vfs privmxvfs = {
        1,
        sizeof(privmx_file),
        MAXPATHNAME,
        0,
        "privmxvfs",
        new std::shared_ptr<PrivmxExtFS>(std::make_shared<PrivmxExtFS>(true)),
        privmxOpen,
        privmxDelete,
        privmxAccess,
        privmxFullPathname,
        privmxDlOpen,
        privmxDlError,
        privmxDlSym,
        privmxDlClose,
        privmxRandomness,
        privmxSleep,
        privmxCurrentTime,
        nullptr, // xGetLastError      (version 2+)
        nullptr, // xCurrentTimeInt64  (version 2+)
        nullptr, // xSetSystemCall     (version 3+)
        nullptr, // xGetSystemCall     (version 3+)
        nullptr, // xNextSystemCall    (version 3+)
    };
    return &privmxvfs;
}
}
