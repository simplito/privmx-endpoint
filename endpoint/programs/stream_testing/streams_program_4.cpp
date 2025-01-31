
#include <wx/wx.h>
#include <wx/rawbmp.h>
#include <wx/rawbmp.h>
#include <wx/dcgraph.h>

#include <iostream>
#include <sstream>
#include <string>
#include <fstream>
#include <vector>
#include <thread>
#include <mutex>

// #include <privmx/utils/IniFileReader.hpp>
#include <privmx/endpoint/core/Exception.hpp>

#include <privmx/endpoint/core/Config.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/ConnectionImpl.hpp>
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
wxBitmap RGBAintoBitmap(int w, int h, unsigned char *rgba ) {
   wxBitmap b = wxBitmap(w, h, 32);
   PixelData bmdata(b);
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
    wxBitmap bmp = wxBitmap(MAX_VIDEO_W, MAX_VIDEO_H, 32);
    bool haveFrame = false;
};

VideoPanel::VideoPanel(wxWindow * parent) :
    wxPanel(parent, wxID_ANY, wxDefaultPosition, wxDefaultSize)
{
    this->SetBackgroundColour(wxColor(100, 100, 200));
    this->Bind(wxEVT_PAINT, &VideoPanel::OnPaint, this);
}

void VideoPanel::Render(int64_t w, int64_t h, std::shared_ptr<privmx::endpoint::stream::Frame> frame) {
    
    std::cout << w << " - " << h << " frame Size" << std::endl;
    auto panel_size = this->GetClientSize();
    // std::cout << panel_size.GetWidth() << " - " << panel_size.GetHeight() << " board Size" << std::endl;
    double scaleW = (double)panel_size.GetWidth() / w;
    double scaleH = (double)panel_size.GetHeight() / h;
    double scale = scaleW < scaleH ? scaleW : scaleH;
    // std::cout << scaleW << " - " << scaleH << " board scale" << std::endl;
    int64_t W =  scale * w;
    int64_t H =  scale * h;
    // std::cout << W << " - " << H << " IMG Size" << std::endl;
    {
        std::unique_lock<std::mutex> lock(m); 
        if(H < 1 || W < 1) return;
        haveFrame = true;
        // picDataVector.reserve(4*w*h);
        // frame->ConvertToRGBA(&picDataVector[0], 1, w, h);
        // bmp = RGBAintoBitmap(w, h, &picDataVector[0]);
        picDataVector.reserve(4*W*H);
        frame->ConvertToRGBA(&picDataVector[0], 1, W, H);
        bmp = RGBAintoBitmap(W, H, &picDataVector[0]);
    }
    this->Refresh();
}

void VideoPanel::OnPaint(wxPaintEvent& event)
{
    std::unique_lock<std::mutex> lock(m);
    wxPaintDC dc(this);
    dc.Clear();
    if(haveFrame) {
        dc.DrawBitmap(bmp.GetSubBitmap(wxRect(0, 0, bmp.GetWidth(), bmp.GetHeight())), 0, 0, false);
    }
}


class MyFrame : public wxFrame
{
public:
    MyFrame();
    void Connect(std::string privKey, std::string solutionId, std::string url);
    void PublishToStreamRoom(std::string streamRoomId);
    void JoinToStreamRoom(std::string streamRoomId);
private:
    void OnFrame(int64_t w, int64_t h, std::shared_ptr<privmx::endpoint::stream::Frame> frame, const std::string id);
    void OnResize(wxSizeEvent& event);
    std::mutex m;
    wxGridSizer* sizer;
    std::map<std::string, VideoPanel*> mapOfVideoPanels;
    VideoPanel* TMPVideoPanel;


    wxPanel* m_board;
    std::vector<unsigned char> picData_vector = std::vector<unsigned char>(4 * MAX_VIDEO_W * MAX_VIDEO_W);
    wxBitmap bmp = wxBitmap(MAX_VIDEO_W, MAX_VIDEO_H, 32);
    int tmp = 0;

    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<stream::StreamApi> streamApi;
};


 
bool MyApp::OnInit()
{
    MyFrame *appFrame = new MyFrame();
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
    Refresh(); 
    event.Skip(); 
}

MyFrame::MyFrame()
    : wxFrame(nullptr, wxID_ANY, "Video Board", wxDefaultPosition, wxDefaultSize)
{
    
    sizer = new wxGridSizer(2);
    this->SetSizer(sizer);
    this->Bind(wxEVT_SIZE, &MyFrame::OnResize , this);

    crypto::CryptoApi cryptoApi = crypto::CryptoApi::create();
    std::string privKey = "KxVnzhhH2zMpumuhzBRoAC6dv9a7pKEzoKuftjP5Vr4MGYoAbgn8";
    Connect(privKey, "fc47c4e4-e1dc-414a-afa4-71d436398cfc", "http://webrtc2.s24.simplito.com:3000");
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
    PublishToStreamRoom(streamRoomId);
    JoinToStreamRoom(streamRoomId);
}

void MyFrame::Connect(std::string privKey, std::string solutionId, std::string url) {
    connection = std::make_shared<core::Connection>(core::Connection::connect(privKey, solutionId, url));
    streamApi = std::make_shared<stream::StreamApi>(stream::StreamApi::create(*connection));
}

void MyFrame::PublishToStreamRoom(std::string streamRoomId) {
    auto streamId = streamApi->createStream(streamRoomId);
    auto listAudioRecordingDevices = streamApi->listAudioRecordingDevices();
    streamApi->trackAdd(streamId, stream::DeviceType::Audio);
    auto listVideoRecordingDevices = streamApi->listVideoRecordingDevices();
    streamApi->trackAdd(streamId, stream::DeviceType::Video);
    streamApi->publishStream(streamId);
}

void MyFrame::JoinToStreamRoom(std::string streamRoomId) {
    auto streamlist = streamApi->listStreams(streamRoomId);
    std::vector<int64_t> streamsId;
    for(int i = 0; i < streamlist.size(); i++) {
        streamsId.push_back(streamlist[i].streamId);
    }
    stream::streamJoinSettings ssettings {
        .OnFrame=[&](int64_t w, int64_t h, std::shared_ptr<privmx::endpoint::stream::Frame> frame, const std::string id) {
            this->OnFrame(w, h, frame, id);
        }
    };
    streamApi->joinStream(streamRoomId, streamsId, ssettings);
}

void MyFrame::OnFrame(int64_t w, int64_t h, std::shared_ptr<privmx::endpoint::stream::Frame> frame, const std::string id) {
    auto it = mapOfVideoPanels.find(id);
    VideoPanel* videoPanel;
    if (it == mapOfVideoPanels.end()) {
        //add video panel 
        videoPanel = new VideoPanel(this);
        mapOfVideoPanels[id] = videoPanel;
        sizer->Add(videoPanel, 1, wxEXPAND | wxALL,5);

        // //TMP
        // TMPVideoPanel = new VideoPanel(this);
        // mapOfVideoPanels[id+"TMP"] = videoPanel;
        // sizer->Add(TMPVideoPanel, 1, wxEXPAND | wxALL,5);
        Layout();
    } else {
        videoPanel = mapOfVideoPanels[id];
    }
    videoPanel->Render(w,h,frame);
    // TMPVideoPanel->Render(w,h,frame);
}
 