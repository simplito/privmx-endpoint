# Deduplication Opportunities in `endpoint/`

## 1. Exception macros — 7 files, ~91 lines

**Pattern:** `DECLARE_SCOPE_ENDPOINT_EXCEPTION` and `DECLARE_ENDPOINT_EXCEPTION` macros are
copy-pasted verbatim into every module's `*Exception.hpp`.

**Files:**
- `core/include_pub/.../CoreException.hpp`
- `thread/include_pub/.../ThreadException.hpp`
- `store/include_pub/.../StoreException.hpp`
- `kvdb/include_pub/.../KvdbException.hpp`
- `inbox/include_pub/.../InboxException.hpp`
- `stream/stream/include_pub/.../StreamException.hpp`
- `event/include_pub/.../EventException.hpp`

**Fix:** Move the two macro definitions to a single
`core/include_pub/privmx/endpoint/core/ExceptionMacros.hpp` and `#include` it everywhere else.
Saves ~13 lines × 7 files ≈ **91 lines**.
**Uriagat comment:**
Must check how current docks works - it was added to fix doc generation
---

## 2. DataSchemaStrategy V5 `getDIOAndAssertIntegrity` — 7 files, ~28 lines

**Pattern:** Every V5 strategy's implementation is a one-liner delegation:
```cpp
DataIntegrityObject getDIOAndAssertIntegrity(const EncryptedXxx& encData) const {
    return _encryptor.getDIOAndAssertIntegrity(encData);
}
```

**Files:** ThreadDataSchemaStrategyV5, StoreDataSchemaStrategyV5, KvdbDataSchemaStrategyV5,
KvdbEntryDataSchemaStrategyV5, MessageDataSchemaStrategyV5, FileDataSchemaStrategyV5,
StreamRoomDataSchemaStrategyV5.

**Fix:** Move the implementation to the base `TypedDataSchemaStrategy<TServer, TEncryptedV5, TDecrypted>`
(or V5 base class) as a non-virtual template method that calls `_encryptor.getDIOAndAssertIntegrity`.
Saves ~4 lines × 7 files ≈ **28 lines**.

**Uriagat comment:**
I think use V5 base class is best also probably can help with encrypt i decrypt
---

## 3. DataSchemaStrategy decrypt pattern — 8 files, ~50 lines

**Pattern:** All V4/V5 strategies share the same 2-branch decrypt body:
```cpp
if (encKey.statusCode == 0) {
    return _encryptor.decrypt(encryptedData, encKey.key);
} else {
    auto result = _encryptor.extractPublic(encryptedData);
    result.statusCode = encKey.statusCode;
    return result;
}
```

**Files:** ThreadDataSchemaStrategyV4/V5, StoreDataSchemaStrategyV4/V5,
KvdbDataSchemaStrategyV5, MessageDataSchemaStrategyV4/V5, EntryDataSchemaStrategyV5,
FileDataSchemaStrategyV4/V5, StreamRoomDataSchemaStrategyV5.

**Fix:** Add a `decryptOrExtractPublic(encryptedData, encKey)` helper in the base strategy class.
Saves ~6 lines × 8+ files ≈ **50+ lines**.

**Uriagat comment:**
I think use V5 base class is best also probably can help with encrypt i decrypt
---

## 4. DataSchemaStrategy `makeErrorResult` — 13 files, ~90 lines

**Pattern:** All strategies implement:
```cpp
return {
    MapperClass::toLibObject(serverObj, {}, {}, {}, errorCode, version),
    core::DataIntegrityObject{}
};
```
The shape is identical; only the mapper class and version enum differ.

**Files:** All V4 and V5 strategy .cpp files (13 implementations).

**Fix:** Move to the `TypedDataSchemaStrategy` base as a template method that calls a
virtual or CRTP `toLibError(serverObj, errorCode)` hook.
Saves ~7 lines × 13 files ≈ **90 lines**.

**Uriagat comment:**
Look good - still inbox can be problematic
---

## 5. DataSchemaMapper structure — 8 files, ~250 lines

**Pattern:** Every mapper (Thread, Store, Kvdb, Inbox, StreamRoom, Message, File, KvdbEntry)
has the same 5-part structure:
1. Constructor that registers strategies into `_strategyMapper`
2. `encrypt()` delegating to the active strategy
3. `decrypt()` calling `_strategyMapper.dispatch(...)`
4. `getDataStructureVersion()` via `DataSchemaMapperUtils::mapVersionedData`
5. `validateDataIntegrity()` / `assertDataIntegrity()` wrapping with `toStatusCode`
6. `validateDecryptAndConvert*()` calling a batch util

**Files:** All 8 mapper .cpp files.

**Fix:** The `_strategyMapper` + `dispatch` boilerplate could be pulled into a CRTP or template
base `DataSchemaMapperBase<TServer, TLib>`. Each mapper only overrides `getDataStructureVersion`
and provides its strategy registrations in the constructor.
Saves ~30 lines × 8 files ≈ **250 lines**.

**Uriagat comment:**
Look good
---

## 6. Server model field macros — 5 containers × 3 structures, ~180 lines

**Pattern:** The `CONTAINER_CREATE_MODEL_FIELDS`, `CONTAINER_UPDATE_MODEL_FIELDS`, and
`CONTAINER_INFO_FIELDS` macros in each module's `ServerTypes.hpp` are nearly identical
(differ only in the container-specific name like `threadId` vs `storeId`).

**Files:**
- `thread/include/.../ServerTypes.hpp`
- `store/include/.../ServerTypes.hpp`
- `kvdb/include/.../ServerTypes.hpp`
- `inbox/include/.../ServerTypes.hpp`
- `stream/stream/include/.../ServerTypes.hpp`

**Fix:** Define base field macros `CONTAINER_CREATE_MODEL_FIELDS(F)`,
`CONTAINER_UPDATE_MODEL_FIELDS(F)`, `CONTAINER_INFO_FIELDS(F)` in
`core/include/.../ServerTypes.hpp` and compose them with module-specific fields.
Saves ~36 lines × 5 containers ≈ **180 lines**.
**Uriagat comment:**
NOPE

---

## 7. ApiImpl: `*ToModuleKeys` converters — 4 files, ~28 lines

**Pattern:** Every container ApiImpl has an identical converter:
```cpp
core::ModuleKeys containerToModuleKeys(server::Container c) {
    return core::ModuleKeys{
        .keys = c.keys,
        .currentKeyId = c.keyId,
        .moduleSchemaVersion = _dataSchemaMapper.getDataStructureVersion(c.data.back()),
        .moduleResourceId = c.resourceId.value_or(""),
        .contextId = c.contextId
    };
}
```

**Files:** ThreadApiImpl, StoreApiImpl, KvdbApiImpl, InboxApiImpl.

**Fix:** Template method in `ModuleBaseApi` that takes the container server type and a
callable for `getDataStructureVersion`. Saves ~7 lines × 4 files ≈ **28 lines**.
**Uriagat comment:**
it's looks promising, but can be problematic in event and inbox
---

## 8. ApiImpl: subscription management — 4 files, ~36 lines  

**Pattern:** `subscribeFor`, `unsubscribeFrom`, `buildSubscriptionQuery` are copy-pasted
across all container ApiImpls. They differ only in the subscription query builder.

**Files:** ThreadApiImpl, StoreApiImpl, KvdbApiImpl, InboxApiImpl.

**Fix:** Implement in `ModuleBaseApi` with a virtual `buildSubscriptionQuery` hook.
Saves ~9 lines × 4 files ≈ **36 lines**.
**Uriagat comment:**
Nope - because 
_eventMiddleware
<module>::SubscriberImpl <- each module have different

---

## 9. ApiImpl: event notification routing — 4 files, ~280 lines // 

**Pattern:** `processNotificationEvent` in each ApiImpl is a long if-else chain over event
type strings (`containerCreated`, `containerUpdated`, `containerDeleted`, `entryCreated`, …).
The structure is identical; only the server type, mapper call, and event builder differ.

**Files:** ThreadApiImpl (~80 lines), StoreApiImpl (~85 lines), KvdbApiImpl (~83 lines),
InboxApiImpl (~70 lines).

**Fix:** An event-type dispatch table in `ModuleBaseApi` with registered typed handlers
reduces each module to registering 5–8 lambdas instead of an 80-line if-else chain.
Saves ~70 lines × 4 files ≈ **280+ lines**.

**Uriagat comment:**
i don't so; 
creating registerNotificationHandler in moduleApi creates processNotificationEvent less readable;


---

## 10. ApiImpl: container update orchestration — 4 files, ~180 lines // looks good

**Pattern:** `updateThread`, `updateStore`, `updateKvdb`, `updateInbox` all execute the
same 6-step sequence: get current container → extract keys → verify secret →
resolve user changes → prepare new keys → prepare missing keys for new users.

**Files:** ThreadApiImpl, StoreApiImpl, KvdbApiImpl, InboxApiImpl.

**Fix:** Extract to a template helper in `ModuleBaseApi` with module-specific hooks for
name differences. Saves ~45 lines × 4 files ≈ **180 lines**.
**Uriagat comment:**
not tested it's looks promising
---

## 11. ApiImpl: key-refresh-on-InvalidKey retry — 4 files, ~48 lines // looks good

**Pattern:** Write operations (`sendMessage`, `setEntry`, `storeFileFinalizeWrite`, …) all
wrap the operation in:
```cpp
try {
    return doOperation(..., getModuleKeys(id));
} catch (InvalidKeyException) {
    return doOperation(..., getNewModuleKeysAndUpdateCache(id));
}
```

**Files:** ThreadApiImpl, StoreApiImpl, KvdbApiImpl, InboxApiImpl.

**Fix:** Template helper `withKeyRefresh<T>(id, callable)` in `ModuleBaseApi`.
Saves ~12 lines × 4 files ≈ **48 lines**.
**Uriagat comment:**
not tested it's looks promising - extra cleanup in keyCache is always appreciated
---

## Summary

| # | Area | Files | Est. lines saved |
|---|------|-------|-----------------|
| 1 | Exception macros | 7 | 91 |
| 2 | `getDIOAndAssertIntegrity` delegation | 7 | 28 |
| 3 | Strategy decrypt pattern | 8 | 50 |
| 4 | Strategy `makeErrorResult` | 13 | 90 |
| 5 | DataSchemaMapper structure | 8 | 250 |
| 6 | Server model field macros | 5 containers | 180 |
| 7 | `*ToModuleKeys` converters | 4 | 28 |
| 8 | Subscription management | 4 | 36 |
| 9 | Event notification routing | 4 | 280 |
| 10 | Container update orchestration | 4 | 180 |
| 11 | Key-refresh retry | 4 | 48 |
| | **Total** | | **~1 261 lines** |

Items 1–3 are low-risk, mechanical changes.
Items 4–5 require careful CRTP/template design.
Items 7–11 touch ApiImpl business logic and benefit from integration test coverage before
and after the refactor.
