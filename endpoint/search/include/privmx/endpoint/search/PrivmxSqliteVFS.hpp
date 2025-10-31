/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef _PRIVMXLIB_ENDPOINT_SEARCH_PRIVMXSQLITEVFS_HPP_
#define _PRIVMXLIB_ENDPOINT_SEARCH_PRIVMXSQLITEVFS_HPP_

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



#define MAXPATHNAME 512

namespace privmx {
namespace endpoint {
namespace search {


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

static int privmxClose(sqlite3_file *pFile) {
    std::shared_ptr<PrivmxFile> file = extractPrivmxFile(pFile);
    file->close();
    return SQLITE_OK;
}

static int privmxRead(sqlite3_file *pFile, void *zBuf, int iAmt, sqlite3_int64 iOfst) {
    // l("Read", iAmt, iOfst);
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

static int privmxWrite(sqlite3_file *pFile, const void *zBuf, int iAmt, sqlite3_int64 iOfst) {
    // l("Write", iAmt, iOfst);
    std::shared_ptr<PrivmxFile> file = extractPrivmxFile(pFile);
    file->write(privmx::endpoint::core::Buffer::from((char*)zBuf, iAmt), iOfst);
    return SQLITE_OK;
}

static int privmxTruncate(sqlite3_file *pFile, sqlite3_int64 size) {
    std::shared_ptr<PrivmxFile> file = extractPrivmxFile(pFile);
    file->truncate(size);
    return SQLITE_OK;
}

static int privmxSync(sqlite3_file *pFile, int flags) {
    std::shared_ptr<PrivmxFile> file = extractPrivmxFile(pFile);
    file->sync();
    return SQLITE_OK;
}

static int privmxFileSize(sqlite3_file *pFile, sqlite3_int64 *pSize) {
    std::shared_ptr<PrivmxFile> file = extractPrivmxFile(pFile);
    *pSize = file->getFileSize();
        // l("File size:", *pSize);
    return SQLITE_OK;
}

static int privmxLock(sqlite3_file *pFile, int eLock) {
    std::shared_ptr<PrivmxFile> file = extractPrivmxFile(pFile);
    l("privmxLock", eLock, file->fh);
    return SQLITE_OK;
}

static int privmxUnlock(sqlite3_file *pFile, int eLock) {
    std::shared_ptr<PrivmxFile> file = extractPrivmxFile(pFile);
    l("privmxUnlock", eLock, file->fh);
    return SQLITE_OK;
}

static int privmxCheckReservedLock(sqlite3_file *pFile, int *pResOut) {
    std::shared_ptr<PrivmxFile> file = extractPrivmxFile(pFile);
    l("privmxCheckReservedLock", file->fh);
    *pResOut = 0;
    return SQLITE_OK;
}

static int privmxFileControl(sqlite3_file *pFile, int op, void *pArg) {
    std::shared_ptr<PrivmxFile> file = extractPrivmxFile(pFile);
    l("privmxFileControl", op, file->fh);
    return SQLITE_NOTFOUND;
}

static int privmxSectorSize(sqlite3_file *pFile) {
    return 512;
}

static int privmxDeviceCharacteristics(sqlite3_file *pFile) {
    return 0;
}

static const sqlite3_io_methods PrivmxIoMethods = {
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


static int privmxOpen(sqlite3_vfs *pVfs, const char *zName, sqlite3_file *pFile, int flags, int *pOutFlags) {
    privmx_file *file = (privmx_file*)pFile;
    std::memset(file, 0, sizeof(privmx_file));
    file->pmxFile = new std::shared_ptr<PrivmxFile>();
    file->base.pMethods = &PrivmxIoMethods;
    if (pOutFlags) *pOutFlags = flags;
    std::shared_ptr<PrivmxExtFS> fs = extractPrivmxExtFS(pVfs);
    file->pmxFile = new std::shared_ptr<PrivmxFile>(fs->openFile(zName));
    return SQLITE_OK;
}


static int privmxDelete(sqlite3_vfs *pVfs, const char *zName, int syncDir) {
    l("Delete", zName);
    return SQLITE_OK;
}

static int privmxAccess(sqlite3_vfs *pVfs, const char *zName, int flags, int *pResOut) {
    l("Access", zName, flags);
    *pResOut = 0;
    return SQLITE_OK;
}

static int privmxFullPathname(sqlite3_vfs *pVfs, const char *zName, int nOut, char *zOut) {
    l("privmxFullPathname", zName, nOut);
    sqlite3_snprintf(nOut, zOut, "%s", zName);
    return SQLITE_OK;
}

static void *privmxDlOpen(sqlite3_vfs *pVfs, const char *zFilename) {
    l("privmxDlOpen", zFilename);
    return 0;
}

static void privmxDlError(sqlite3_vfs *pVfs, int nByte, char *zErrMsg) {
    l("privmxDlError", nByte, zErrMsg);

}

static void (*privmxDlSym(sqlite3_vfs *pVfs, void *p, const char *zSymbol))(void) {
    l("privmxDlSym", zSymbol);
    return 0;
}

static void privmxDlClose(sqlite3_vfs *pVfs, void *p) {
    l("privmxDlClose");
}

static int privmxRandomness(sqlite3_vfs *pVfs, int nByte, char *zOut) {
    l("privmxRandomness");
    memset(zOut, 0, nByte);
    return SQLITE_OK;
}

static int privmxSleep(sqlite3_vfs *pVfs, int microseconds) {
    l("privmxSleep");
    sleep(microseconds / 1000000);
    usleep(microseconds % 1000000);
    return microseconds;
}

static int privmxCurrentTime(sqlite3_vfs *pVfs, double *pTime) {
    l("privmxCurrentTime");
    *pTime = 0.0;
    return SQLITE_OK;
}

static sqlite3_vfs PrivmxVfs = {
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

}




}  // namespace search
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_SEARCH_PRIVMXSQLITEVFS_HPP_
