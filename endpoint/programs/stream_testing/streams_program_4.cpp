
#include <wx/wx.h>
#include <wx/rawbmp.h>
#include <wx/rawbmp.h>
#include <wx/dcgraph.h>
#include <wx/textentry.h>

#include <iostream>
#include <sstream>
#include <string>
#include <fstream>
#include <vector>
#include <thread>
#include <mutex>
#include <map>

#include <privmx/endpoint/core/Exception.hpp>

#include <privmx/endpoint/core/Config.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/event/EventApi.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>
#include <privmx/endpoint/stream/StreamApi.hpp>
#include <privmx/endpoint/stream/Types.hpp>
#include <privmx/endpoint/crypto/CryptoApi.hpp>
#include <privmx/utils/PrivmxException.hpp>


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

private:
    void OnPaint(wxPaintEvent& event);
    std::mutex m;
    std::vector<unsigned char> picDataVector;
    std::shared_ptr<wxBitmap> bmp = std::make_shared<wxBitmap>(MAX_VIDEO_W, MAX_VIDEO_H, 32);
    bool haveFrame = false;
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
    {
        std::unique_lock<std::mutex> lock(m); 
        bmp = RGBAintoBitmap(W, H, &picDataVector[0]);
        haveFrame = true;
    }
    
}

void VideoPanel::OnPaint(wxPaintEvent& event)
{
    wxPaintDC dc(this);
    dc.Clear();
    if(haveFrame) {
        std::unique_lock<std::mutex> lock(m);
        std::shared_ptr<wxBitmap> tmp_bmp = bmp;
        dc.DrawBitmap(tmp_bmp->GetSubBitmap(wxRect(0, 0, tmp_bmp->GetWidth(), tmp_bmp->GetHeight())), 0, 0, false);
    }
}


class MyFrame : public wxFrame
{
public:
    MyFrame();
    void Connect(std::string privKey, std::string solutionId, std::string url);
    void PublishToStreamRoom(std::string streamRoomId);
    void JoinToStreamRoom(std::string streamRoomId);
    std::vector<privmx::endpoint::stream::StreamRoom> ListStreamRooms(std::string streamRoomId);
private:
    void OnFrame(int64_t w, int64_t h, std::shared_ptr<privmx::endpoint::stream::Frame> frame, const std::string id);
    void OnResize(wxSizeEvent& event);
    std::mutex m;
    wxGridSizer* sizer;
    std::map<std::string, std::shared_ptr<VideoPanel>> mapOfVideoPanels;

    wxPanel* m_board;


    wxGridSizer* controlSizer;
    wxButton* connectButton;
    wxButton* joinButton;
    wxButton* publishButton;
    wxTextCtrl* hostURLInput;
    wxTextCtrl* privKeyInput;
    wxTextCtrl* solutionIdInput;
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
    event.Skip(); 
}

MyFrame::MyFrame()
    : wxFrame(nullptr, wxID_ANY, "Video Board", wxDefaultPosition, wxDefaultSize)
{
    controlSizer = new wxGridSizer(2);
    m_board = new wxPanel(this, wxID_ANY);
    connectButton = new wxButton(this->m_board, wxID_ANY, "Connect");
    joinButton = new wxButton(this->m_board, wxID_ANY, "Join");
    publishButton = new wxButton(this->m_board, wxID_ANY, "Publish");
    hostURLInput = new wxTextCtrl(this->m_board, wxID_ANY, "http://webrtc2.s24.simplito.com:3000");
    privKeyInput = new wxTextCtrl(this->m_board, wxID_ANY, "KxVnzhhH2zMpumuhzBRoAC6dv9a7pKEzoKuftjP5Vr4MGYoAbgn8");
    solutionIdInput = new wxTextCtrl(this->m_board, wxID_ANY, "fc47c4e4-e1dc-414a-afa4-71d436398cfc");
    streamRoomIdInput = new wxTextCtrl(this->m_board, wxID_ANY, "stream room Id");


    controlSizer->Add(hostURLInput, 1, wxEXPAND | wxALL,5);
    controlSizer->Add(privKeyInput, 1, wxEXPAND | wxALL,5);
    controlSizer->Add(solutionIdInput, 1, wxEXPAND | wxALL,5);
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
            Connect(privKeyInput->GetValue().ToStdString(), solutionIdInput->GetValue().ToStdString(), hostURLInput->GetValue().ToStdString());
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
    sizer->Add(m_board, 1, wxEXPAND | wxALL,5);
    this->SetSizerAndFit(sizer);

    std::thread t([&]() {
        while(true) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));

            std::for_each(mapOfVideoPanels.begin(), mapOfVideoPanels.end(), [&](const auto& p) {if(p.second!=nullptr) p.second->Refresh(); ;});
        }
    }); 
    t.detach();
}

void MyFrame::Connect(std::string privKey, std::string solutionId, std::string url) {
    connection = std::make_shared<core::Connection>(core::Connection::connect(privKey, solutionId, url));
    eventApi = std::make_shared<event::EventApi>(event::EventApi::create(*connection));
    streamApi = std::make_shared<stream::StreamApi>(stream::StreamApi::create(*connection, *eventApi));
    crypto::CryptoApi cryptoApi = crypto::CryptoApi::create();
    auto context = connection->listContexts({.skip=0, .limit=1, .sortOrder="asc"}).readItems[0];
    auto streamRoomList = streamApi->listStreamRooms(context.contextId, {.skip=0, .limit=1, .sortOrder="asc"});
    std::string streamRoomId;

    if(streamRoomList.readItems.size()==0) {
        auto pubKey = cryptoApi.derivePublicKey(privKey);
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

void MyFrame::PublishToStreamRoom(std::string streamRoomId) {
    auto streamId = streamApi->createStream(streamRoomId);
    auto listAudioRecordingDevices = streamApi->listAudioRecordingDevices();
    streamApi->trackAdd(streamId,  stream::TrackParam{{.id=0, .type=stream::DeviceType::Audio}, .params_JSON="{}"});
    auto listVideoRecordingDevices = streamApi->listVideoRecordingDevices();
    streamApi->trackAdd(streamId,  stream::TrackParam{{.id=0, .type=stream::DeviceType::Video}, .params_JSON="{}"});
    streamApi->publishStream(streamId);
}

void MyFrame::JoinToStreamRoom(std::string streamRoomId) {
    auto streamlist = streamApi->listStreams(streamRoomId);
    std::vector<int64_t> streamsId;
    if(streamlist.size() == 0) return;
    for(int i = 0; i < streamlist.size(); i++) {
        streamsId.push_back(streamlist[i].streamId);
    }
    stream::StreamJoinSettings ssettings {
        .OnFrame=[&](int64_t w, int64_t h, std::shared_ptr<privmx::endpoint::stream::Frame> frame, const std::string id) {
            this->OnFrame(w, h, frame, id);
        }
    };
    streamApi->joinStream(streamRoomId, streamsId, ssettings);
}

std::vector<privmx::endpoint::stream::StreamRoom> MyFrame::ListStreamRooms(std::string contextId) {
    auto streamlist = streamApi->listStreamRooms(contextId, core::PagingQuery{.skip=0, .limit=100, .sortOrder="desc"}); 
    return streamlist.readItems;
}

void MyFrame::OnFrame(int64_t w, int64_t h, std::shared_ptr<privmx::endpoint::stream::Frame> frame, const std::string id) {
    auto it = mapOfVideoPanels.find(id);
    std::shared_ptr<VideoPanel> videoPanel ;
    if (it == mapOfVideoPanels.end()) {
        //add video panel 
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
 