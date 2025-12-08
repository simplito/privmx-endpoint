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
#include "privmx/endpoint/store/StoreApi.hpp"
#include "privmx/endpoint/kvdb/KvdbApi.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/search/Types.hpp"

#include <sqlite3.h>

#include <exception>
#include <stdexcept>
#include <iostream>
#include <unistd.h>

#include "privmx/endpoint/search/PrivmxFS.hpp"

#include "privmx/endpoint/search/PrivmxSqliteVFS.hpp"

using namespace privmx::endpoint::search;

extern "C" {

struct privmx_file
{
    sqlite3_file base;
    void* pmxFile;
};
typedef privmx_file privmx_file;

}

inline std::shared_ptr<PrivmxFile> extractPrivmxFile(sqlite3_file *pFile) {
    return *((std::shared_ptr<PrivmxFile>*)((privmx_file*)pFile)->pmxFile);
}

inline std::shared_ptr<PrivmxExtFS> extractPrivmxExtFS(sqlite3_vfs *pVfs) {
    return *((std::shared_ptr<PrivmxExtFS>*)(pVfs->pAppData));
}

extern "C" {

int privmxClose(sqlite3_file *pFile) {
    std::shared_ptr<PrivmxFile> file = extractPrivmxFile(pFile);
    try {
        file->close();
    } catch (...) {
        return SQLITE_IOERR;
    }
    return SQLITE_OK;
}

int privmxRead(sqlite3_file *pFile, void *zBuf, int iAmt, sqlite3_int64 iOfst) {
    std::shared_ptr<PrivmxFile> file = extractPrivmxFile(pFile);
    try {
        auto data = file->read(iAmt, iOfst);
        if (data.size() > iAmt) {
            return SQLITE_IOERR_READ;
        }
        std::memcpy(zBuf, data.data(), data.size());
        if (iAmt > data.size()) {
            std::memset(&((char*)zBuf)[data.size()], 0, iAmt - data.size());
        }
    } catch (...) {
        std::memset(zBuf, 0, iAmt);
        return SQLITE_IOERR_SHORT_READ;
    }
    return SQLITE_OK;
}

int privmxWrite(sqlite3_file *pFile, const void *zBuf, int iAmt, sqlite3_int64 iOfst) {
    std::shared_ptr<PrivmxFile> file = extractPrivmxFile(pFile);
    try {
        file->write(privmx::endpoint::core::Buffer::from((char*)zBuf, iAmt), iOfst);
    } catch (...) {
        return SQLITE_IOERR_WRITE;
    }
    return SQLITE_OK;
}

int privmxTruncate(sqlite3_file *pFile, sqlite3_int64 size) {
    std::shared_ptr<PrivmxFile> file = extractPrivmxFile(pFile);
    try {
        file->truncate(size);
    } catch (...) {
        return SQLITE_IOERR;
    }
    return SQLITE_OK;
}

int privmxSync(sqlite3_file *pFile, int flags) {
    std::shared_ptr<PrivmxFile> file = extractPrivmxFile(pFile);
    try {
        file->sync();
    } catch (...) {
        return SQLITE_IOERR;
    }
    return SQLITE_OK;
}

int privmxFileSize(sqlite3_file *pFile, sqlite3_int64 *pSize) {
    std::shared_ptr<PrivmxFile> file = extractPrivmxFile(pFile);
    try {
        *pSize = file->getFileSize();
    } catch (...) {
        return SQLITE_IOERR;
    }
    return SQLITE_OK;
}

int privmxLock(sqlite3_file *pFile, int eLock) {
    std::shared_ptr<PrivmxFile> file = extractPrivmxFile(pFile);
    try {
        if (file->lock((privmx::endpoint::search::LockLevel)eLock)) {
            return SQLITE_OK;
        } else {
            return SQLITE_BUSY;
        }
    } catch (...) {
        return SQLITE_IOERR;
    }
}

int privmxUnlock(sqlite3_file *pFile, int eLock) {
    std::shared_ptr<PrivmxFile> file = extractPrivmxFile(pFile);
    try {
        if (file->unlock((privmx::endpoint::search::LockLevel)eLock)) {
            return SQLITE_OK;
        } else {
            return SQLITE_IOERR;
        }
    } catch (...) {
        return SQLITE_IOERR;
    }
}

int privmxCheckReservedLock(sqlite3_file *pFile, int *pResOut) {
    std::shared_ptr<PrivmxFile> file = extractPrivmxFile(pFile);
    *pResOut = 0;
    try {
        *pResOut = file->checkReservedLock();
        return SQLITE_OK;
    } catch (...) {
        return SQLITE_IOERR;
    }
}

int privmxFileControl(sqlite3_file *pFile, int op, void *pArg) {
    std::shared_ptr<PrivmxFile> file = extractPrivmxFile(pFile);
    return SQLITE_NOTFOUND;
}

int privmxSectorSize(sqlite3_file *pFile) {
    return 512;
}

int privmxDeviceCharacteristics(sqlite3_file *pFile) {
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
    privmxDeviceCharacteristics
};


int privmxOpen(sqlite3_vfs *pVfs, const char *zName, sqlite3_file *pFile, int flags, int *pOutFlags) {
    privmx_file *file = (privmx_file*)pFile;
    std::memset(file, 0, sizeof(privmx_file));
    file->pmxFile = new std::shared_ptr<PrivmxFile>();
    file->base.pMethods = &PrivmxIoMethods;
    if (pOutFlags) *pOutFlags = flags;
    std::shared_ptr<PrivmxExtFS> fs = extractPrivmxExtFS(pVfs);
    try {
        file->pmxFile = new std::shared_ptr<PrivmxFile>(fs->openFile(zName));
    } catch (...) {
        return SQLITE_IOERR;
    }
    return SQLITE_OK;
}


int privmxDelete(sqlite3_vfs *pVfs, const char *zName, int syncDir) {
    std::shared_ptr<PrivmxExtFS> fs = extractPrivmxExtFS(pVfs);
    try {
        fs->deleteFile(zName);
    } catch (...) {
        return SQLITE_IOERR;
    }
    return SQLITE_OK;
}

int privmxAccess(sqlite3_vfs *pVfs, const char *zName, int flags, int *pResOut) {
    std::shared_ptr<PrivmxExtFS> fs = extractPrivmxExtFS(pVfs);
    try {
        *pResOut = fs->access(zName);
    } catch (...) {
        return SQLITE_IOERR;
    }
    return SQLITE_OK;
}

int privmxFullPathname(sqlite3_vfs *pVfs, const char *zName, int nOut, char *zOut) {
    std::shared_ptr<PrivmxExtFS> fs = extractPrivmxExtFS(pVfs);
    try {
        sqlite3_snprintf(nOut, zOut, "%s", fs->fullPathname(zName).c_str());
    } catch (...) {
        return SQLITE_IOERR;
    }
    return SQLITE_OK;
}

void *privmxDlOpen(sqlite3_vfs *pVfs, const char *zFilename) {
    return 0;
}

void privmxDlError(sqlite3_vfs *pVfs, int nByte, char *zErrMsg) {

}

void (*privmxDlSym(sqlite3_vfs *pVfs, void *p, const char *zSymbol))(void) {
    return 0;
}

void privmxDlClose(sqlite3_vfs *pVfs, void *p) {
}

int privmxRandomness(sqlite3_vfs *pVfs, int nByte, char *zOut) {
    memset(zOut, 0, nByte);
    return SQLITE_OK;
}

int privmxSleep(sqlite3_vfs *pVfs, int microseconds) {
    sleep(microseconds / 1000000);
    usleep(microseconds % 1000000);
    return microseconds;
}

int privmxCurrentTime(sqlite3_vfs *pVfs, double *pTime) {
    time_t t = time(0);
    *pTime = t/86400.0 + 2440587.5;
    return SQLITE_OK;
}

sqlite3_vfs* sqlite3_privmxvfs() {
    static sqlite3_vfs privmxvfs = {
        1,
        sizeof(privmx_file),
        MAXPATHNAME,
        0,
        "privmxvfs",
        new std::shared_ptr<PrivmxExtFS>(std::make_shared<PrivmxExtFS>()),
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
    };
    return &privmxvfs;
}

}
