
#include <wx/wx.h>
#include <wx/rawbmp.h>
#include <wx/rawbmp.h>
#include <wx/dcgraph.h>
#include <wx/textentry.h>
#include <wx/glcanvas.h>

#include <iostream>
#include <sstream>
#include <string>
#include <fstream>
#include <vector>
#include <thread>
#include <mutex>
#include <map>

#include <privmx/utils/Debug.hpp>
#include <privmx/utils/CancellationToken.hpp>
#include <privmx/endpoint/core/Exception.hpp>

#include <privmx/endpoint/core/Config.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/Events.hpp>
#include <privmx/endpoint/core/EventQueue.hpp>
#include <privmx/endpoint/crypto/CryptoApi.hpp>
#include <privmx/endpoint/event/EventApi.hpp>
#include <privmx/endpoint/event/Events.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/thread/Events.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>
#include <privmx/endpoint/store/Events.hpp>
#include <privmx/endpoint/stream/StreamApi.hpp>
#include <privmx/endpoint/stream/Events.hpp>
#include <privmx/endpoint/stream/Types.hpp>
#include <privmx/utils/PrivmxException.hpp>
#include <Poco/URI.h>
#include <privmx/rpc/channel/ChannelEnv.hpp>
#include <privmx/utils/Utils.hpp>


using namespace std;
using namespace privmx::endpoint;


// Max HD resolution
#define MAX_VIDEO_W 1280
#define MAX_VIDEO_H 720

typedef wxAlphaPixelData PixelData;

// when creating the bitmap, use an explicit depth of 32!
std::shared_ptr<wxBitmap> RGBAintoBitmap(int w, int h, unsigned char *rgba ) {
   std::shared_ptr<wxBitmap> b = std::make_shared<wxBitmap>(w, h, 32);
   PixelData bmdata(*b);
   PixelData::Iterator dst(bmdata);
   for( int y = 0; y < h; y++)
   {
      dst.MoveTo(bmdata, 0, y);
      for(int x = 0; x < w; x++)
      {
         // wxBitmap contains rgb values pre-multiplied with alpha
         unsigned char a = rgba[0];
         // you could use "/256" here to speed up the code,
         // but at the price of being not 100% accurate
         dst.Red() = rgba[3] * a / 255;
         dst.Green() = rgba[2] * a / 255;
         dst.Blue() = rgba[1] * a / 255;
         dst.Alpha() = a;
         dst++;
         rgba += 4;
      }
   }

   return b;
}

class MyApp : public wxApp {
public:
    bool OnInit() override;

private:
};
 
wxIMPLEMENT_APP(MyApp);
 
class VideoPanel : public wxPanel {
public:
    VideoPanel(wxWindow * parent);
    void Render(int64_t w, int64_t h, std::shared_ptr<privmx::endpoint::stream::Frame> frame);
    std::atomic_bool haveNewFrame = false;

private:
    void OnPaint(wxPaintEvent& event);
    std::mutex m;
    std::vector<unsigned char> picDataVector;
    std::shared_ptr<wxBitmap> bmp = std::make_shared<wxBitmap>(MAX_VIDEO_W, MAX_VIDEO_H, 32);
};

VideoPanel::VideoPanel(wxWindow * parent) :
    wxPanel(parent, wxID_ANY, wxDefaultPosition, wxSize(320,180))
{
    this->SetBackgroundColour(wxColor(100, 100, 200));
    this->Bind(wxEVT_PAINT, &VideoPanel::OnPaint, this);
}

void VideoPanel::Render(int64_t w, int64_t h, std::shared_ptr<privmx::endpoint::stream::Frame> frame) {
    auto panel_size = this->GetClientSize();
    double scaleW = (double)panel_size.GetWidth() / w;
    double scaleH = (double)panel_size.GetHeight() / h;
    double scale = scaleW < scaleH ? scaleW : scaleH;
    int64_t W =  scale * w;
    int64_t H =  scale * h;
    if(H < 1 || W < 1) return;
    picDataVector.reserve(4*W*H);
    frame->ConvertToRGBA(&picDataVector[0], 1, W, H);
    std::shared_ptr<wxBitmap> tmp_bmp = RGBAintoBitmap(W, H, &picDataVector[0]);
    {
        std::unique_lock<std::mutex> lock(m); 
        bmp = tmp_bmp;
        haveNewFrame = true;
    }
    
}

void VideoPanel::OnPaint(wxPaintEvent& event)
{
    wxPaintDC dc(this);
    if(haveNewFrame) {
        std::shared_ptr<wxBitmap> tmp_bmp;
        {
            std::unique_lock<std::mutex> lock(m);
            tmp_bmp = bmp;
            haveNewFrame = false;
        }
        dc.DrawBitmap(tmp_bmp->GetSubBitmap(wxRect(0, 0, tmp_bmp->GetWidth(), tmp_bmp->GetHeight())), 0, 0, false);
    }
}


class MyFrame : public wxFrame
{
public:
    MyFrame();
    void Connect(std::string login, std::string password, std::string url);
    void PublishToStreamRoom(std::string streamRoomId);
    void JoinToStreamRoom(std::string streamRoomId);
    std::vector<privmx::endpoint::stream::StreamRoom> ListStreamRooms(std::string streamRoomId);
private:
    void OnFrame(int64_t w, int64_t h, std::shared_ptr<privmx::endpoint::stream::Frame> frame, const std::string id);
    void OnResize(wxSizeEvent& event);
    void OnExit(wxCloseEvent& event);

    privmx::utils::CancellationToken cancellationToken;
    std::mutex m;
    std::shared_mutex _videoPanels;
    wxGridSizer* sizer;
    std::map<std::string, std::shared_ptr<VideoPanel>> mapOfVideoPanels;

    wxPanel* m_board;


    wxGridSizer* controlSizer;
    wxButton* connectButton;
    wxButton* joinButton;
    wxButton* publishButton;
    wxTextCtrl* hostURLInput;
    wxTextCtrl* loginInput;
    wxTextCtrl* passwordInput;
    wxTextCtrl* streamRoomIdInput;
    wxPanel* checkbox_board;
    wxBoxSizer* checkBoxSizer;
    wxCheckBox* brickKeyManager;
    wxCheckBox* hideBrokenFrames;


    std::vector<unsigned char> picData_vector = std::vector<unsigned char>(4 * MAX_VIDEO_W * MAX_VIDEO_W);
    wxBitmap bmp = wxBitmap(MAX_VIDEO_W, MAX_VIDEO_H, 32);
    int tmp = 0;
    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<event::EventApi> eventApi;
    std::shared_ptr<stream::StreamApi> streamApi;
    std::thread _event_handler;
    std::thread _renderer_handler;
    std::optional<int64_t> joinedStream;
    std::optional<int64_t> publishedStream;

};


 
bool MyApp::OnInit()
{
    MyFrame *appFrame = new MyFrame();
    appFrame->SetClientSize(600, 400);
    appFrame->Center();
    appFrame->Show(true);
    return true;
}
 
void MyFrame::OnResize(wxSizeEvent& event) {
    int w = this->GetClientSize().GetWidth();
    int numberOfMaxCol = w / (320 + 10);
    numberOfMaxCol = numberOfMaxCol != 0 ? numberOfMaxCol : 1;
    int numberOfVideos = mapOfVideoPanels.size() != 0 ? mapOfVideoPanels.size() : 1;
    int numberCol = numberOfMaxCol < numberOfVideos ? numberOfMaxCol : numberOfVideos;
    sizer->SetCols(numberCol);
    {
        std::shared_lock<std::shared_mutex> lock(_videoPanels);
        // this->Refresh();
        std::for_each(mapOfVideoPanels.begin(), mapOfVideoPanels.end(), [&](const auto& p) {
            p.second->haveNewFrame = true; 
        });
    }
    event.Skip(); 
}

void MyFrame::OnExit(wxCloseEvent& event) {
    cancellationToken.cancel();
    if(streamApi) {
        if(joinedStream.has_value()) {
            PRIVMX_DEBUG("StreamProgram wx", "OnExit", "Leaving Stream")
            streamApi->leaveStream(joinedStream.value());
        }
        if(publishedStream.has_value()) {
            PRIVMX_DEBUG("StreamProgram wx", "OnExit", "Unpublishing Stream")
            streamApi->unpublishStream(publishedStream.value());
        }
        streamApi.reset();
    }
    if(eventApi) eventApi.reset();
    if(connection) {
        PRIVMX_DEBUG("StreamProgram wx", "OnExit", "Disconnecting")
        connection->disconnect();
        connection.reset();
    }
    privmx::endpoint::core::EventQueue::getInstance().emitBreakEvent();

    PRIVMX_DEBUG("StreamProgram wx", "OnExit", "Join threads")
    if(_event_handler.joinable()) {
        _event_handler.join();
    }
    if(_renderer_handler.joinable()) {
        _renderer_handler.join();
    }
    PRIVMX_DEBUG("StreamProgram wx", "OnExit", "Closed")
    Destroy();
}

MyFrame::MyFrame()
    : wxFrame(nullptr, wxID_ANY, "Video Board", wxDefaultPosition, wxDefaultSize), cancellationToken(privmx::utils::CancellationToken())
{
    controlSizer = new wxGridSizer(2);
    m_board = new wxPanel(this, wxID_ANY);
    connectButton = new wxButton(this->m_board, wxID_ANY, "Connect");
    joinButton = new wxButton(this->m_board, wxID_ANY, "Join");
    publishButton = new wxButton(this->m_board, wxID_ANY, "Publish");
    hostURLInput = new wxTextCtrl(this->m_board, wxID_ANY, "https://webrtc-demo-app-server.test.simplito.com");
    loginInput = new wxTextCtrl(this->m_board, wxID_ANY, "Login");
    passwordInput = new wxTextCtrl(this->m_board, wxID_ANY, "Default password", wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD, wxDefaultValidator);
    streamRoomIdInput = new wxTextCtrl(this->m_board, wxID_ANY, "stream room Id");

    controlSizer->Add(loginInput, 1, wxEXPAND | wxALL,5);
    controlSizer->Add(passwordInput, 1, wxEXPAND | wxALL,5);
    controlSizer->Add(hostURLInput, 1, wxEXPAND | wxALL,5);
    controlSizer->Add(connectButton, 1, wxEXPAND | wxALL,5);
    
    controlSizer->Add(streamRoomIdInput, 1, wxEXPAND | wxALL,5);
    controlSizer->Add(joinButton, 1, wxEXPAND | wxALL,5);
    controlSizer->Add(publishButton, 1, wxEXPAND | wxALL,5);

    checkbox_board = new wxPanel(this, wxID_ANY);
    checkBoxSizer = new wxBoxSizer(wxVERTICAL);
    brickKeyManager = new wxCheckBox(this->checkbox_board, wxID_ANY, "brick Key Manager");
    hideBrokenFrames = new wxCheckBox(this->checkbox_board, wxID_ANY, "hide broken frames");
    checkBoxSizer->Add(brickKeyManager, 1, wxALIGN_CENTER);
    checkBoxSizer->Add(hideBrokenFrames, 1, wxALIGN_CENTER);

    this->brickKeyManager->Bind(wxEVT_CHECKBOX, [&](wxCommandEvent& event) {
        
        try {
            if(streamApi == nullptr) {
                brickKeyManager->SetValue(false);
                return;
            }
            streamApi->keyManagement(brickKeyManager->GetValue());
        } catch (const privmx::endpoint::core::Exception& e) {

        };
    });
    this->hideBrokenFrames->Bind(wxEVT_CHECKBOX, [&](wxCommandEvent& event) {
        try {
            if(streamApi == nullptr) {
                hideBrokenFrames->SetValue(false);
                return;
            }
            streamApi->dropBrokenFrames(hideBrokenFrames->GetValue());
        } catch (const privmx::endpoint::core::Exception& e) {
            hideBrokenFrames->SetValue(false);
        };
    });

    checkbox_board->SetSizerAndFit(checkBoxSizer);
    controlSizer->Add(checkbox_board, 1, wxEXPAND | wxALL,5);


    this->connectButton->Bind(wxEVT_BUTTON, [&](wxCommandEvent& event) {
        try {
            Connect(loginInput->GetValue().ToStdString(), passwordInput->GetValue().ToStdString(), hostURLInput->GetValue().ToStdString());
        } catch (const privmx::endpoint::core::Exception& e) {

        };
    });

    this->joinButton->Bind(wxEVT_BUTTON, [&](wxCommandEvent& event) {
        try {
            if(streamApi == nullptr) return;
            JoinToStreamRoom(streamRoomIdInput->GetValue().ToStdString());
        } catch (const privmx::endpoint::core::Exception& e) {

        };
    });
    this->publishButton->Bind(wxEVT_BUTTON, [&](wxCommandEvent& event) {
        try {
            if(streamApi == nullptr) return;
            PublishToStreamRoom(streamRoomIdInput->GetValue().ToStdString());
        } catch (const privmx::endpoint::core::Exception& e) {

        };
    });

    m_board->SetSizerAndFit(controlSizer);
    
    sizer = new wxGridSizer(2);
    this->Bind(wxEVT_SIZE, &MyFrame::OnResize , this);
    this->Bind(wxEVT_CLOSE_WINDOW, &MyFrame::OnExit , this);
    sizer->Add(m_board, 1, wxEXPAND | wxALL,5);
    this->SetSizerAndFit(sizer);

    _renderer_handler = std::thread([&]() {
        try {
            while(!cancellationToken.isCancelled()) {
                cancellationToken.sleep(std::chrono::milliseconds(50));
                {
                    std::shared_lock<std::shared_mutex> lock(_videoPanels);
                    // this->Refresh();
                    std::for_each(mapOfVideoPanels.begin(), mapOfVideoPanels.end(), [&](const auto& p) {
                        if(p.second!=nullptr && p.second->haveNewFrame) {
                            p.second->Refresh();
                        } 
                    });
                }
            }
        } catch (const privmx::utils::OperationCancelledException& e) {
            return;
        }
    }); 
    _event_handler = std::thread([&]() {
        auto eventQueue = privmx::endpoint::core::EventQueue::getInstance();
        while (!cancellationToken.isCancelled()) {
            auto eventHolder = eventQueue.waitEvent();
            if(privmx::endpoint::core::Events::isLibBreakEvent(eventHolder)) {
                return;
            }
            PRIVMX_DEBUG("StreamProgram wx", "Event recived", eventHolder.toJSON())
            if(privmx::endpoint::stream::Events::isStreamPublishedEvent(eventHolder)) {
                auto eventData = privmx::endpoint::stream::Events::extractStreamPublishedEvent(eventHolder);
                if(eventData.data.streamRoomId == streamRoomIdInput->GetValue()) {
                    PRIVMX_DEBUG("StreamProgram wx", "isStreamPublishedEvent", "Reseting VideoPanels")
                    std::unique_lock<std::shared_mutex> lock(_videoPanels);
                    mapOfVideoPanels.clear();
                    Layout();
                }
            } else if (privmx::endpoint::stream::Events::isStreamUnpublishedEvent(eventHolder)) {
                auto eventData = privmx::endpoint::stream::Events::extractStreamUnpublishedEvent(eventHolder);
                if(eventData.data.streamRoomId == streamRoomIdInput->GetValue()) {

                    PRIVMX_DEBUG("StreamProgram wx", "isStreamUnpublishedEvent", "Reseting VideoPanels")
                    std::unique_lock<std::shared_mutex> lock(_videoPanels);
                    mapOfVideoPanels.clear();
                    Layout();
                }
            } 
        }
    });
}

void MyFrame::Connect(std::string login, std::string password, std::string url) {
    // generate KeyPair
    privmx::endpoint::crypto::CryptoApi cryptoApi = privmx::endpoint::crypto::CryptoApi();
    auto privKey = cryptoApi.derivePrivateKey2(password, login);
    auto pubKey = cryptoApi.derivePublicKey(privKey);
    // setup ttpChannel
    Poco::URI uri {url};
    std::string contentType {"application/json"};
    auto httpChannel {privmx::rpc::ChannelEnv::getHttpChannel(uri, false)};
    // get Info
    auto result_info = httpChannel->send("", "/info", {}, privmx::utils::CancellationToken::create(), contentType, true, false).get();
    std::cout << result_info << std::endl;
    auto info = privmx::utils::Utils::parseJsonObject(result_info);
    

    std::string bridgeUrl = "";
    if(info->has("bridgeUrl")) bridgeUrl = info->getValue<std::string>("bridgeUrl");
    std::string solutionId = "";
    if(info->has("solutionId")) solutionId = info->getValue<std::string>("solutionId");
    std::string contextId = "";
    if(info->has("contextId")) contextId = info->getValue<std::string>("contextId");
    std::string streamRoomId = "";
    if(info->has("streamRoomId")) streamRoomId = info->getValue<std::string>("streamRoomId");
    streamRoomIdInput->SetValue(streamRoomId);
    // admin account
    std::string adminUserId = "";
    if(info->has("adminUserId")) adminUserId = info->getValue<std::string>("adminUserId");
    std::string adminUserPubKey = "";
    if(info->has("adminUserPubKey")) adminUserPubKey = info->getValue<std::string>("adminUserPubKey");
    std::string adminUserPrivKey = "";
    if(info->has("adminUserPrivKey")) adminUserPrivKey = info->getValue<std::string>("adminUserPrivKey");


    Poco::JSON::Object::Ptr request_json = new Poco::JSON::Object();
    request_json->set("contextId", contextId);
    request_json->set("userId", login);
    request_json->set("userPubKey", pubKey);
    auto requestString {privmx::utils::Utils::stringify(request_json)};
    std::cout << requestString << std::endl;
    auto result_addUser = httpChannel->send(requestString, "/addUser", {}, privmx::utils::CancellationToken::create(), contentType, false, false).get();
    std::cout << result_addUser << std::endl;
    auto addUser = privmx::utils::Utils::parseJsonObject(result_addUser);
    if(addUser->has("success") && addUser->getValue<bool>("success")) {
        PRIVMX_DEBUG("StreamProgram wx", "Connect", "Connected with Application Server")
        try {
            connection = std::make_shared<core::Connection>(core::Connection::connect(privKey, solutionId, bridgeUrl));
            eventApi = std::make_shared<event::EventApi>(event::EventApi::create(*connection));
            streamApi = std::make_shared<stream::StreamApi>(stream::StreamApi::create(*connection, *eventApi));
        } catch (const privmx::endpoint::core::Exception& e) {
            PRIVMX_DEBUG("StreamProgram wx", "Connect", "Connection To bridge failed")
        }
        try {
            PRIVMX_DEBUG("StreamProgram wx", "Connect", "Getting StreamRoom")
            auto room = streamApi->getStreamRoom(streamRoomId);
            PRIVMX_DEBUG("StreamProgram wx", "Connect", "StreamRoom status code = " + std::to_string(room.statusCode));
        } catch (const privmx::endpoint::core::Exception& e) {
            PRIVMX_DEBUG("StreamProgram wx", "Connect", "User not added to StreamRoom")
            auto admin_connection = std::make_shared<core::Connection>(core::Connection::connect(adminUserPrivKey, solutionId, bridgeUrl));
            auto admin_streamApi = std::make_shared<stream::StreamApi>(stream::StreamApi::create(*admin_connection, *eventApi));
            bool stop = false;
            for (size_t i = 0;!stop;i++) {
                PRIVMX_DEBUG("StreamProgram wx", "Connect", "Admin: Getting StreamRoomInfo")
                auto users_list = admin_connection->listContextUsers(contextId, core::PagingQuery{0, 100, "desc"});
                std::vector<privmx::endpoint::core::UserWithPubKey> users;
                for(const auto& userInfo: users_list.readItems) {
                    users.push_back(userInfo.user);
                }
                privmx::endpoint::stream::StreamRoom streamRoomInfo;
                try {
                    streamRoomInfo = admin_streamApi->getStreamRoom(streamRoomId);
                } catch (const privmx::endpoint::core::Exception& e) {
                    PRIVMX_DEBUG("StreamProgram wx", "Connect", "Admin: Updating StreamRoomInfo")
                    streamRoomIdInput->SetValue(admin_streamApi->createStreamRoom(
                        contextId,
                        users,
                        users,
                        core::Buffer::from("publicMeta"),
                        core::Buffer::from("privateMeta"),
                        std::nullopt
                    ));
                    stop = true;
                    break;
                }
                try {
                    
                    PRIVMX_DEBUG("StreamProgram wx", "Connect", "Admin: Updating StreamRoomInfo")
                    admin_streamApi->updateStreamRoom(
                        streamRoomId,
                        users,
                        users,
                        streamRoomInfo.publicMeta,
                        streamRoomInfo.privateMeta,
                        streamRoomInfo.version,
                        false,
                        false,
                        std::nullopt
                    );
                    stop = true;
                    break;
                } catch (const privmx::endpoint::core::Exception& e) {
                    std::cout << "Failed to add user to Stream Room, try: " << i+1 << std::endl;
                    continue;
                }
            }
            admin_connection->disconnect();
        }

    } else {
        PRIVMX_DEBUG("StreamProgram wx", "Connect", "Failed in connecting with Application Server, using backup default User")
        loginInput->SetValue("backup Default User");
        connection = std::make_shared<core::Connection>(core::Connection::connect(
            "L3DdgfGagr2yGFEHs1FcRQRGrpa4nwQKdPcfPiHxcDcZeEb3wYaN", 
            "fc47c4e4-e1dc-414a-afa4-71d436398cfc", 
            "http://webrtc2.s24.simplito.com:3000"
        ));
        eventApi = std::make_shared<event::EventApi>(event::EventApi::create(*connection));
        streamApi = std::make_shared<stream::StreamApi>(stream::StreamApi::create(*connection, *eventApi));
        auto context = connection->listContexts({.skip=0, .limit=1, .sortOrder="asc"}).readItems[0];
        contextId = context.contextId;
        auto streamRoomList = streamApi->listStreamRooms(context.contextId, {.skip=0, .limit=1, .sortOrder="asc"});
        std::string streamRoomId;

        if(streamRoomList.readItems.size() == 0 || streamRoomList.readItems[0].statusCode != 0) {
            if(streamRoomList.readItems.size() > 0) streamApi->deleteStreamRoom(streamRoomList.readItems[0].streamRoomId);
            std::vector<privmx::endpoint::core::UserWithPubKey> users = {
                privmx::endpoint::core::UserWithPubKey{.userId="patryk", .pubKey="51ciywf56WuDKxyEuquMsfoydEK2NavoFtFBvoKWEi7VuqHkur"},
                privmx::endpoint::core::UserWithPubKey{.userId="user1",  .pubKey="8RUGiizsLszXAfWXEaPxjrcnXCsgd48zCHmmK6ng2cZCquMoeZ"}
            };
            streamRoomId = streamApi->createStreamRoom(
                context.contextId,
                users,
                users,
                privmx::endpoint::core::Buffer::from(""),
                privmx::endpoint::core::Buffer::from(""),
                std::nullopt
            );
            
        } else {
            streamRoomId = streamRoomList.readItems[0].streamRoomId;
        }
        streamRoomIdInput->SetValue(streamRoomId);
    }
    streamApi->subscribeFor({
        streamApi->buildSubscriptionQuery(stream::EventType::STREAM_JOIN, stream::EventSelectorType::CONTEXT_ID, contextId),
        streamApi->buildSubscriptionQuery(stream::EventType::STREAM_LEAVE, stream::EventSelectorType::CONTEXT_ID, contextId),
        streamApi->buildSubscriptionQuery(stream::EventType::STREAM_PUBLISH, stream::EventSelectorType::CONTEXT_ID, contextId),
        streamApi->buildSubscriptionQuery(stream::EventType::STREAM_UNPUBLISH, stream::EventSelectorType::CONTEXT_ID, contextId)
    });
    
}

void MyFrame::PublishToStreamRoom(std::string streamRoomId) {
    if(publishedStream.has_value()) {
        PRIVMX_DEBUG("StreamProgram wx", "PublishToStreamRoom", "Unpublishing Stream")
        streamApi->unpublishStream(publishedStream.value());
    }
    auto streamId = streamApi->createStream(streamRoomId);
    publishedStream = streamId;
    auto listAudioRecordingDevices = streamApi->listAudioRecordingDevices();
    streamApi->trackAdd(streamId,  stream::TrackParam{{.id=0, .type=stream::DeviceType::Audio}, .params_JSON="{}"});
    auto listVideoRecordingDevices = streamApi->listVideoRecordingDevices();
    streamApi->trackAdd(streamId,  stream::TrackParam{{.id=0, .type=stream::DeviceType::Video}, .params_JSON="{}"});
    streamApi->publishStream(streamId);
}

void MyFrame::JoinToStreamRoom(std::string streamRoomId) {
    
    PRIVMX_DEBUG("StreamProgram wx", "JoinToStreamRoom", "streamApi->listStreams StreamRoomId: " + streamRoomId);
    auto streamlist = streamApi->listStreams(streamRoomId);
    PRIVMX_DEBUG("StreamProgram wx", "JoinToStreamRoom", "streamApi->listStreams.size(): " + std::to_string(streamlist.size()));
    std::vector<int64_t> streamsId;
    if(streamlist.size() == 0) return;
    for(int i = 0; i < streamlist.size(); i++) {
        PRIVMX_DEBUG("StreamProgram wx", "JoinToStreamRoom", "Stream Id: " + std::to_string(streamlist[i].streamId));
        streamsId.push_back(streamlist[i].streamId);
    }
    stream::StreamJoinSettings ssettings {
        .OnFrame=[&](int64_t w, int64_t h, std::shared_ptr<privmx::endpoint::stream::Frame> frame, const std::string id) {
            this->OnFrame(w, h, frame, id);
        }
    };

    if(joinedStream.has_value()) {
        PRIVMX_DEBUG("StreamProgram wx", "PublishToStreamRoom", "Leaving Stream")
        streamApi->leaveStream(joinedStream.value());
        {
            std::unique_lock<std::shared_mutex> lock(_videoPanels);
            mapOfVideoPanels.clear();
            Layout();
        }
        PRIVMX_DEBUG("StreamProgram wx", "PublishToStreamRoom", "Reseting VideoPanels")
        std::unique_lock<std::shared_mutex> lock(_videoPanels);
    }
    joinedStream = streamApi->joinStream(streamRoomId, streamsId, ssettings);
}

std::vector<privmx::endpoint::stream::StreamRoom> MyFrame::ListStreamRooms(std::string contextId) {
    auto streamlist = streamApi->listStreamRooms(contextId, core::PagingQuery{.skip=0, .limit=100, .sortOrder="desc"}); 
    return streamlist.readItems;
}

void MyFrame::OnFrame(int64_t w, int64_t h, std::shared_ptr<privmx::endpoint::stream::Frame> frame, const std::string id) {
    std::shared_ptr<VideoPanel> videoPanel;
    {
        std::unique_lock<std::shared_mutex> lock(_videoPanels);
        auto it = mapOfVideoPanels.find(id);
        
        if (it == mapOfVideoPanels.end()) {
            //add video panel 
            PRIVMX_DEBUG("StreamProgram wx", "Adding New", "VideoPanel, Frame id: " + id)
            videoPanel = std::make_shared<VideoPanel>(this);
            mapOfVideoPanels[id] = videoPanel;
            sizer->Add(videoPanel.get(), 1, wxEXPAND | wxALL,5);
            Layout();
        } else {
            videoPanel = mapOfVideoPanels[id];
        }
        if(videoPanel != nullptr) {
            videoPanel->Render(w,h,frame);
        }
    }
}
 