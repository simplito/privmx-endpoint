#include <gtest/gtest.h>
#include "../utils/BaseTest.hpp"
#include "../utils/FalseUserVerifierInterface.hpp"
#include <privmx/endpoint/core/Exception.hpp>
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/utils/Utils.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>
#include <privmx/endpoint/store/VarSerializer.hpp>
#include <privmx/endpoint/kvdb/KvdbApi.hpp>
#include <privmx/endpoint/kvdb/VarSerializer.hpp>
#include <privmx/endpoint/search/SearchApi.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/UserVerifierInterface.hpp>

using namespace privmx::endpoint;

class FalseUserVerifierInterface: public virtual core::UserVerifierInterface {
public:
    std::vector<bool> verify(const std::vector<core::VerificationRequest>& request) override {
        return std::vector<bool>(request.size(), false);
    };
};

class TrueUserVerifierInterface: public virtual core::UserVerifierInterface {
public:
    std::vector<bool> verify(const std::vector<core::VerificationRequest>& request) override {
        return std::vector<bool>(request.size(), true);
    };
};

enum ConnectionType {
    User1,
    User2,
    Public
};

class SearchTest : public privmx::test::BaseTest {
protected:
    SearchTest() : BaseTest(privmx::test::BaseTestMode::online) {}
    void connectAs(ConnectionType type) {
        if(type == ConnectionType::User1) {
            connection = std::make_shared<core::Connection>(
                core::Connection::connect(
                    reader->getString("Login.user_1_privKey"),
                    reader->getString("Login.solutionId"),
                    getPlatformUrl(reader->getString("Login.instanceUrl"))
                )
            );
        } else if(type == ConnectionType::User2) {
            connection = std::make_shared<core::Connection>(
                core::Connection::connect(
                    reader->getString("Login.user_2_privKey"),
                    reader->getString("Login.solutionId"),
                    getPlatformUrl(reader->getString("Login.instanceUrl"))
                )
            );
        } else if(type == ConnectionType::Public) {
            connection = std::make_shared<core::Connection>(
                core::Connection::connectPublic(
                    reader->getString("Login.solutionId"),
                    getPlatformUrl(reader->getString("Login.instanceUrl"))
                )
            );
        }
        storeApi = std::make_shared<store::StoreApi>(
            store::StoreApi::create(
                *connection
            )
        );
        kvdbApi = std::make_shared<kvdb::KvdbApi>(
            kvdb::KvdbApi::create(
                *connection
            )
        );
        searchApi = std::make_shared<search::SearchApi>(
            search::SearchApi::create(
                *connection,
                *storeApi,
                *kvdbApi
            )
        );
    }
    void disconnect() {
        connection->disconnect();
        searchApi.reset();
        kvdbApi.reset();
        storeApi.reset();
        connection.reset();
    }
    void customSetUp() override {
        reader = new Poco::Util::IniFileConfiguration(INI_FILE_PATH);
        connection = std::make_shared<core::Connection>(
            core::Connection::connect(
                reader->getString("Login.user_1_privKey"),
                reader->getString("Login.solutionId"),
                getPlatformUrl(reader->getString("Login.instanceUrl"))
            )
        );
        storeApi = std::make_shared<store::StoreApi>(
            store::StoreApi::create(
                *connection
            )
        );
        kvdbApi = std::make_shared<kvdb::KvdbApi>(
            kvdb::KvdbApi::create(
                *connection
            )
        );
        searchApi = std::make_shared<search::SearchApi>(
            search::SearchApi::create(
                *connection,
                *storeApi,
                *kvdbApi
            )
        );
    }
    void customTearDown() override { // tmp segfault fix
        connection.reset();
        storeApi.reset();
        kvdbApi.reset();
        searchApi.reset();
        reader.reset();
        core::EventQueueImpl::getInstance()->clear();
    }
    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<store::StoreApi> storeApi;
    std::shared_ptr<kvdb::KvdbApi> kvdbApi;
    std::shared_ptr<search::SearchApi> searchApi;
    Poco::Util::IniFileConfiguration::Ptr reader;
    core::VarSerializer _serializer = core::VarSerializer({});
};

TEST_F(SearchTest, getSearchIndex) {
    // incorrect id
    EXPECT_THROW({
        searchApi->getSearchIndex(
            reader->getString("SearchIndex_1.contextId")
        );
    }, core::Exception);
     // correct SearchIndexId
    search::SearchIndex index;
    EXPECT_NO_THROW({
        index = searchApi->getSearchIndex(
            reader->getString("SearchIndex_1.indexId")
        );
    });
    EXPECT_EQ(index.contextId, reader->getString("SearchIndex_1.contextId"));
    EXPECT_EQ(index.indexId, reader->getString("SearchIndex_1.indexId"));
    EXPECT_EQ(index.createDate, reader->getInt64("SearchIndex_1.createDate"));
    EXPECT_EQ(index.creator, reader->getString("SearchIndex_1.creator"));
    EXPECT_EQ(index.lastModificationDate, reader->getInt64("SearchIndex_1.lastModificationDate"));
    EXPECT_EQ(index.lastModifier, reader->getString("SearchIndex_1.lastModifier"));
    EXPECT_EQ(index.version, reader->getInt64("SearchIndex_1.version"));
    EXPECT_EQ(static_cast<int64_t>(index.mode), reader->getInt64("SearchIndex_1.mode"));
    EXPECT_EQ(index.statusCode, 0);
    EXPECT_EQ(index.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("SearchIndex_1.publicMeta_inHex")));
    EXPECT_EQ(index.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("SearchIndex_1.uploaded_publicMeta_inHex")));
    EXPECT_EQ(index.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("SearchIndex_1.privateMeta_inHex")));
    EXPECT_EQ(index.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("SearchIndex_1.uploaded_privateMeta_inHex")));

    EXPECT_EQ(index.version, 1);
    EXPECT_EQ(index.creator, reader->getString("Login.user_1_id"));
    EXPECT_EQ(index.lastModifier, reader->getString("Login.user_1_id"));
    EXPECT_EQ(index.users.size(), 1);
    if(index.users.size() == 1) {
        EXPECT_EQ(index.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(index.managers.size(), 1);
    if(index.managers.size() == 1) {
        EXPECT_EQ(index.managers[0], reader->getString("Login.user_1_id"));
    }
}

TEST_F(SearchTest, listSearchIndexes_incorrect_input_data) {
    // incorrect contextId
    EXPECT_THROW({
        searchApi->listSearchIndexes(
            reader->getString("SearchIndex_1.indexId"),
            {
                .skip=0,
                .limit=1,
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // limit < 0
    EXPECT_THROW({
        searchApi->listSearchIndexes(
            reader->getString("Context_1.contextId"),
            {
                .skip=0,
                .limit=-1,
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // limit == 0
    EXPECT_THROW({
        searchApi->listSearchIndexes(
            reader->getString("Context_1.contextId"),
            {
                .skip=0,
                .limit=0,
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // incorrect sortOrder
    EXPECT_THROW({
        searchApi->listSearchIndexes(
            reader->getString("Context_1.contextId"),
            {
                .skip=0,
                .limit=1,
                .sortOrder="BLACH"
            }
        );
    }, core::Exception);
    // incorrect lastId
    EXPECT_THROW({
        searchApi->listSearchIndexes(
            reader->getString("Context_1.contextId"),
            {
                .skip=0,
                .limit=1,
                .sortOrder="desc",
                .lastId=reader->getString("Context_1.contextId")
            }
        );
    }, core::Exception);
    // incorrect queryAsJson
    EXPECT_THROW({
        searchApi->listSearchIndexes(
            reader->getString("Context_1.contextId"),
            {
                .skip=0,
                .limit=1,
                .sortOrder="desc",
                .lastId=std::nullopt,
                .queryAsJson="{BLACH,}"
            }
        );
    }, core::InvalidParamsException);
    // incorrect sortBy
    EXPECT_THROW({
        searchApi->listSearchIndexes(
            reader->getString("Context_1.contextId"),
            core::PagingQuery{
                .skip=0,
                .limit=1,
                .sortOrder="desc",
                .lastId=std::nullopt,
                .sortBy="blach",
                .queryAsJson=std::nullopt
            }
        );
    }, core::InvalidParamsException);
}

TEST_F(SearchTest, listSearchIndexes_correct_input_data) {
    core::PagingList<search::SearchIndex> listSearchIndexes;
    search::SearchIndex searchIndex;
    // {.skip=4, .limit=1, .sortOrder="desc"}
    EXPECT_NO_THROW({
        listSearchIndexes = searchApi->listSearchIndexes(
            reader->getString("Context_1.contextId"),
            {
                .skip=4,
                .limit=1,
                .sortOrder="desc"
            }
        );
    });
    // {.skip=0, .limit=1, .sortOrder="desc"}
    EXPECT_NO_THROW({
        listSearchIndexes = searchApi->listSearchIndexes(
            reader->getString("Context_1.contextId"),
            {
                .skip=0,
                .limit=1,
                .sortOrder="desc"
            }
        );
    });
    EXPECT_EQ(listSearchIndexes.totalAvailable, 3);
    EXPECT_EQ(listSearchIndexes.readItems.size(), 1);
    if(listSearchIndexes.readItems.size() >= 1) {
        searchIndex = listSearchIndexes.readItems[0];
        EXPECT_EQ(searchIndex.indexId, reader->getString("SearchIndex_3.indexId"));
        EXPECT_EQ(searchIndex.contextId, reader->getString("SearchIndex_3.contextId"));
        EXPECT_EQ(searchIndex.createDate, reader->getInt64("SearchIndex_3.createDate"));
        EXPECT_EQ(searchIndex.creator, reader->getString("SearchIndex_3.creator"));
        EXPECT_EQ(searchIndex.lastModificationDate, reader->getInt64("SearchIndex_3.lastModificationDate"));
        EXPECT_EQ(searchIndex.lastModifier, reader->getString("SearchIndex_3.lastModifier"));
        EXPECT_EQ(searchIndex.version, reader->getInt64("SearchIndex_3.version"));
        EXPECT_EQ(static_cast<int64_t>(searchIndex.mode), reader->getInt64("SearchIndex_3.mode"));
        EXPECT_EQ(searchIndex.statusCode, 0);
        EXPECT_EQ(searchIndex.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("SearchIndex_3.publicMeta_inHex")));
        EXPECT_EQ(searchIndex.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("SearchIndex_3.uploaded_publicMeta_inHex")));
        EXPECT_EQ(searchIndex.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("SearchIndex_3.privateMeta_inHex")));
        EXPECT_EQ(searchIndex.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("SearchIndex_3.uploaded_privateMeta_inHex")));
        EXPECT_EQ(searchIndex.users.size(), 2);
        if(searchIndex.users.size() == 2) {
            EXPECT_EQ(searchIndex.users[0], reader->getString("Login.user_1_id"));
            EXPECT_EQ(searchIndex.users[1], reader->getString("Login.user_2_id"));
        }
        EXPECT_EQ(searchIndex.managers.size(), 1);
        if(searchIndex.managers.size() == 1) {
            EXPECT_EQ(searchIndex.managers[0], reader->getString("Login.user_1_id"));
        }
    }
    // {.skip=1, .limit=3, .sortOrder="asc", .sortBy="createDate"}
    EXPECT_NO_THROW({
        listSearchIndexes = searchApi->listSearchIndexes(
            reader->getString("Context_1.contextId"),
            {
                .skip=1,
                .limit=3,
                .sortOrder="asc"
            }
        );
    });
    EXPECT_EQ(listSearchIndexes.totalAvailable, 3);
    EXPECT_EQ(listSearchIndexes.readItems.size(), 2);
    if(listSearchIndexes.readItems.size() >= 1) {
        searchIndex = listSearchIndexes.readItems[0];
        EXPECT_EQ(searchIndex.indexId, reader->getString("SearchIndex_2.indexId"));
        EXPECT_EQ(searchIndex.contextId, reader->getString("SearchIndex_2.contextId"));
        EXPECT_EQ(searchIndex.createDate, reader->getInt64("SearchIndex_2.createDate"));
        EXPECT_EQ(searchIndex.creator, reader->getString("SearchIndex_2.creator"));
        EXPECT_EQ(searchIndex.lastModificationDate, reader->getInt64("SearchIndex_2.lastModificationDate"));
        EXPECT_EQ(searchIndex.lastModifier, reader->getString("SearchIndex_2.lastModifier"));
        EXPECT_EQ(searchIndex.version, reader->getInt64("SearchIndex_2.version"));
        EXPECT_EQ(searchIndex.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("SearchIndex_2.publicMeta_inHex")));
        EXPECT_EQ(searchIndex.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("SearchIndex_2.uploaded_publicMeta_inHex")));
        EXPECT_EQ(searchIndex.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("SearchIndex_2.privateMeta_inHex")));
        EXPECT_EQ(searchIndex.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("SearchIndex_2.uploaded_privateMeta_inHex")));
        EXPECT_EQ(searchIndex.statusCode, 0);
        EXPECT_EQ(searchIndex.users.size(), 2);
        if(searchIndex.users.size() == 2) {
            EXPECT_EQ(searchIndex.users[0], reader->getString("Login.user_1_id"));
            EXPECT_EQ(searchIndex.users[1], reader->getString("Login.user_2_id"));
        }
        EXPECT_EQ(searchIndex.managers.size(), 2);
        if(searchIndex.managers.size() == 2) {
            EXPECT_EQ(searchIndex.managers[0], reader->getString("Login.user_1_id"));
            EXPECT_EQ(searchIndex.managers[1], reader->getString("Login.user_2_id"));
        }
    }
    if(listSearchIndexes.readItems.size() >= 2) {
        searchIndex = listSearchIndexes.readItems[1];
        EXPECT_EQ(searchIndex.indexId, reader->getString("SearchIndex_3.indexId"));
        EXPECT_EQ(searchIndex.contextId, reader->getString("SearchIndex_3.contextId"));
        EXPECT_EQ(searchIndex.createDate, reader->getInt64("SearchIndex_3.createDate"));
        EXPECT_EQ(searchIndex.creator, reader->getString("SearchIndex_3.creator"));
        EXPECT_EQ(searchIndex.lastModificationDate, reader->getInt64("SearchIndex_3.lastModificationDate"));
        EXPECT_EQ(searchIndex.lastModifier, reader->getString("SearchIndex_3.lastModifier"));
        EXPECT_EQ(searchIndex.version, reader->getInt64("SearchIndex_3.version"));
        EXPECT_EQ(searchIndex.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("SearchIndex_3.publicMeta_inHex")));
        EXPECT_EQ(searchIndex.publicMeta.stdString(), privmx::utils::Hex::toString(reader->getString("SearchIndex_3.uploaded_publicMeta_inHex")));
        EXPECT_EQ(searchIndex.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("SearchIndex_3.privateMeta_inHex")));
        EXPECT_EQ(searchIndex.privateMeta.stdString(), privmx::utils::Hex::toString(reader->getString("SearchIndex_3.uploaded_privateMeta_inHex")));
        EXPECT_EQ(searchIndex.statusCode, 0);
        EXPECT_EQ(searchIndex.users.size(), 2);
        if(searchIndex.users.size() == 2) {
            EXPECT_EQ(searchIndex.users[0], reader->getString("Login.user_1_id"));
            EXPECT_EQ(searchIndex.users[1], reader->getString("Login.user_2_id"));
        }
        EXPECT_EQ(searchIndex.managers.size(), 1);
        if(searchIndex.managers.size() == 1) {
            EXPECT_EQ(searchIndex.managers[0], reader->getString("Login.user_1_id"));
        }
    }
}

TEST_F(SearchTest, openSearchIndex) {
    // incorrect id
    EXPECT_THROW({
        searchApi->openSearchIndex(
            reader->getString("SearchIndex_1.contextId")
        );
    }, core::Exception);
    // multiple opens by singel user
    int64_t indexHandle_1;
    int64_t indexHandle_2;
    EXPECT_NO_THROW({
        indexHandle_1 = searchApi->openSearchIndex(
            reader->getString("SearchIndex_1.indexId")
        );
    });
    EXPECT_NO_THROW({
        indexHandle_2 = searchApi->openSearchIndex(
            reader->getString("SearchIndex_1.indexId")
        );
    });
    // opens by multiple user
    std::shared_ptr<core::Connection> connection_2 = std::make_shared<core::Connection>(
        core::Connection::connect(
            reader->getString("Login.user_2_privKey"),
            reader->getString("Login.solutionId"),
            getPlatformUrl(reader->getString("Login.instanceUrl"))
        )
    );
    std::shared_ptr<store::StoreApi> storeApi_2 = std::make_shared<store::StoreApi>(
        store::StoreApi::create(*connection)
    );
    std::shared_ptr<kvdb::KvdbApi> kvdbApi_2 = std::make_shared<kvdb::KvdbApi>(
        kvdb::KvdbApi::create(*connection)
    );
    std::shared_ptr<search::SearchApi> searchApi_2 = std::make_shared<search::SearchApi>(
        search::SearchApi::create(*connection, *storeApi, *kvdbApi_2)
    );
    int64_t indexHandle_3;
    EXPECT_NO_THROW({
        indexHandle_3 = searchApi_2->openSearchIndex(
            reader->getString("SearchIndex_1.indexId")
        );
    });
}

TEST_F(SearchTest, closeSearchIndex) {
    // incorrect id
    EXPECT_THROW({
        searchApi->closeSearchIndex(
            0
        );
    }, core::Exception);
    // closing opened Index
    int64_t indexHandle_1;
    EXPECT_NO_THROW({
        indexHandle_1 = searchApi->openSearchIndex(
            reader->getString("SearchIndex_1.indexId")
        );
    });
    EXPECT_NO_THROW({
        searchApi->closeSearchIndex(
            indexHandle_1
        );
    });
    // closing closed index
    EXPECT_THROW({
        searchApi->closeSearchIndex(
            indexHandle_1
        );
    }, core::Exception);
}

TEST_F(SearchTest, addDocument) {
    //incorect handle
    EXPECT_THROW({
        searchApi->addDocument(
            0, 
            "doc-nome", "doc-context"
        );
    }, core::Exception);
    // correct indexHandle
    int64_t indexHandle_1;
    EXPECT_NO_THROW({
        indexHandle_1 = searchApi->openSearchIndex(
            reader->getString("SearchIndex_1.indexId")
        );
    });
    EXPECT_NO_THROW({
        searchApi->addDocument(
            indexHandle_1, 
            "doc-nome", "doc-context"
        );
    });
    // using closed index
    EXPECT_NO_THROW({
        searchApi->closeSearchIndex(
            indexHandle_1
        );
    });
    EXPECT_THROW({
        searchApi->addDocument(
            indexHandle_1, 
            "doc-nome", "doc-context"
        );
    }, core::Exception);
}

TEST_F(SearchTest, updateDocument) {
    //incorect handle
    EXPECT_THROW({
        searchApi->updateDocument(
            0, 
            search::Document{
                .documentId=reader->getInt64("SearchIndex_1.doc_1_id"), 
                .name=reader->getString("SearchIndex_1.doc_1_name"), 
                .content="New Document Content"
            }
        );
    }, core::Exception);
    // correct indexHandle
    int64_t indexHandle_1;
    EXPECT_NO_THROW({
        indexHandle_1 = searchApi->openSearchIndex(
            reader->getString("SearchIndex_1.indexId")
        );
    });
    EXPECT_NO_THROW({
        searchApi->updateDocument(
            indexHandle_1, 
            search::Document{
                .documentId=reader->getInt64("SearchIndex_1.doc_1_id"), 
                .name=reader->getString("SearchIndex_1.doc_1_name"), 
                .content="New Document Content"
            }
        );
    });
    // using closed index
    EXPECT_NO_THROW({
        searchApi->closeSearchIndex(
            indexHandle_1
        );
    });
    EXPECT_THROW({
        searchApi->updateDocument(
            indexHandle_1, 
            search::Document{
                .documentId=reader->getInt64("SearchIndex_1.doc_1_id"), 
                .name=reader->getString("SearchIndex_1.doc_1_name"), 
                .content="New Document Content"
            }
        );
    }, core::Exception);
}

TEST_F(SearchTest, updateDocument2) {
    //incorect handle
    EXPECT_THROW({
        searchApi->updateDocument(
            0, 
            search::Document{
                .documentId=reader->getInt64("SearchIndex_1.doc_1_id"), 
                .name=reader->getString("SearchIndex_1.doc_1_name"), 
                .content="Invalid Handle"
            }
        );
    }, core::Exception);
    // correct indexHandle
    int64_t indexHandle_1;
    EXPECT_NO_THROW({
        indexHandle_1 = searchApi->openSearchIndex(
            reader->getString("SearchIndex_1.indexId")
        );
    });
    EXPECT_NO_THROW({
        searchApi->updateDocument(
            indexHandle_1, 
            search::Document{
                .documentId=reader->getInt64("SearchIndex_1.doc_1_id"), 
                .name=reader->getString("SearchIndex_1.doc_1_name"), 
                .content="New Document Content"
            }
        );
    });
    // invalid document Id
    EXPECT_THROW({
        searchApi->updateDocument(
            indexHandle_1, 
            search::Document{
                .documentId=0, 
                .name=reader->getString("SearchIndex_1.doc_1_name"), 
                .content="Using Closed Handle"
            }
        );
    }, core::Exception);
    // using closed index
    EXPECT_NO_THROW({
        searchApi->closeSearchIndex(
            indexHandle_1
        );
    });
    EXPECT_THROW({
        searchApi->updateDocument(
            indexHandle_1, 
            search::Document{
                .documentId=reader->getInt64("SearchIndex_1.doc_1_id"), 
                .name=reader->getString("SearchIndex_1.doc_1_name"), 
                .content="Using Closed Handle"
            }
        );
    }, core::Exception);
}

TEST_F(SearchTest, deleteDocument) {
    //incorect handle
    EXPECT_THROW({
        searchApi->deleteDocument(
            0, 
            reader->getInt64("SearchIndex_1.doc_1_id")
        );
    }, core::Exception);
    int64_t indexHandle_1;
    EXPECT_NO_THROW({
        indexHandle_1 = searchApi->openSearchIndex(
            reader->getString("SearchIndex_1.indexId")
        );
    });
    // correct DocumentId
    EXPECT_NO_THROW({
        searchApi->deleteDocument(
            indexHandle_1, 
            reader->getInt64("SearchIndex_1.doc_1_id")
        );
    });

    //incorect documentId
    EXPECT_THROW({
        searchApi->deleteDocument(
            indexHandle_1, 
            reader->getInt64("SearchIndex_1.doc_1_id")
        );
    }, core::Exception);
    EXPECT_NO_THROW({
        searchApi->closeSearchIndex(
            indexHandle_1
        );
    });
    EXPECT_THROW({
        searchApi->deleteDocument(
            indexHandle_1, 
            reader->getInt64("SearchIndex_1.doc_2_id")
        );
    }, core::Exception);
}

TEST_F(SearchTest, searchDocuments_invalidData) {
    int64_t indexHandle_1;
    EXPECT_NO_THROW({
        indexHandle_1 = searchApi->openSearchIndex(
            reader->getString("SearchIndex_1.indexId")
        );
    });
    // invalid handle
    EXPECT_THROW({
        searchApi->searchDocuments(
            0, 
            reader->getString("SearchIndex_1.docs_common_content_part"),
            {
                .skip=0,
                .limit=-1,
                .sortOrder="asc"
            }
        );
    }, core::Exception);

    // limit < 0
    EXPECT_THROW({
        searchApi->searchDocuments(
            indexHandle_1, 
            reader->getString("SearchIndex_1.docs_common_content_part"),
            {
                .skip=0,
                .limit=-1,
                .sortOrder="asc"
            }
        );
    }, core::Exception);
    // limit == 0
    EXPECT_THROW({
        searchApi->searchDocuments(
            indexHandle_1, 
            reader->getString("SearchIndex_1.docs_common_content_part"),
            {
                .skip=0,
                .limit=0,
                .sortOrder="asc"
            }
        );
    }, core::Exception);
    // incorrect sortOrder
    EXPECT_THROW({
        searchApi->searchDocuments(
            indexHandle_1, 
            reader->getString("SearchIndex_1.docs_common_content_part"),
            {
                .skip=0,
                .limit=1,
                .sortOrder="BLACH"
            }
        );
    }, core::Exception);
    // incorrect queryAsJson
    EXPECT_THROW({
        searchApi->searchDocuments(
            indexHandle_1, 
            reader->getString("SearchIndex_1.docs_common_content_part"),
            {
                .skip=0,
                .limit=1,
                .sortOrder="asc",
                .lastId=std::nullopt,
                .queryAsJson="{BLACH,}"
            }
        );
    }, core::Exception);
    // incorrect sortBy
    EXPECT_THROW({
        searchApi->searchDocuments(
            indexHandle_1, 
            reader->getString("SearchIndex_1.docs_common_content_part"),
            {
                .skip=0,
                .limit=1,
                .sortOrder="asc",
                .lastId=std::nullopt,
                .sortBy="blach",
                .queryAsJson=std::nullopt
            }
        );
    }, core::Exception);
}

TEST_F(SearchTest, searchDocuments_correctData) {
    int64_t indexHandle_1;
    EXPECT_NO_THROW({
        indexHandle_1 = searchApi->openSearchIndex(
            reader->getString("SearchIndex_1.indexId")
        );
    });
    // Non found
    core::PagingList<search::Document> documents;
    EXPECT_NO_THROW({
        documents = searchApi->searchDocuments(
            indexHandle_1, 
            "NON",
            {
                .skip=0,
                .limit=2,
                .sortOrder="asc"
            }
        );
    });
    EXPECT_EQ(documents.totalAvailable, 0);
    // Only one
    EXPECT_NO_THROW({
        documents = searchApi->searchDocuments(
            indexHandle_1, 
            reader->getString("SearchIndex_1.doc_1_content"),
            {
                .skip=0,
                .limit=2,
                .sortOrder="asc"
            }
        );
    });
    EXPECT_EQ(documents.totalAvailable, 1);
    // All
    EXPECT_NO_THROW({
        documents = searchApi->searchDocuments(
            indexHandle_1, 
            reader->getString("SearchIndex_1.docs_common_content_part"),
            {
                .skip=0,
                .limit=2,
                .sortOrder="asc"
            }
        );
    });
    EXPECT_EQ(documents.totalAvailable, 2);
}

TEST_F(SearchTest, falseUserVerifierInterface) {

    int64_t handle = 0;
    handle = searchApi->openSearchIndex(reader->getString("SearchIndex_1.indexId"));
    EXPECT_NO_THROW({
        std::shared_ptr<FalseUserVerifierInterface> falseUserVerifierInterface = std::make_shared<FalseUserVerifierInterface>();
        connection->setUserVerifier(falseUserVerifierInterface);
    });
    core::PagingList<search::SearchIndex> listSearchIndexes;
    EXPECT_NO_THROW({
        listSearchIndexes = searchApi->listSearchIndexes(reader->getString("Context_1.contextId"),{.skip=0, .limit=1, .sortOrder="desc"});
    });
    if(listSearchIndexes.readItems.size() == 1) {
        EXPECT_EQ(listSearchIndexes.readItems[0].statusCode, core::UserVerificationFailureException().getCode());
    } else {
        FAIL();
    }
    EXPECT_THROW({
        searchApi->listDocuments(handle,{.skip=0, .limit=1, .sortOrder="desc"});
    }, core::Exception);


    EXPECT_NO_THROW({
        std::shared_ptr<TrueUserVerifierInterface> trueUserVerifierInterface = std::make_shared<TrueUserVerifierInterface>();
        connection->setUserVerifier(trueUserVerifierInterface);
    });
    EXPECT_NO_THROW({
        searchApi->closeSearchIndex(handle);
    });
}

