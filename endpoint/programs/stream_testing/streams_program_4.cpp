
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
wxBitmap RGBAintoBitmap(int w, int h, unsigned char *rgba )
{
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

class MyApp : public wxApp
{
public:
    bool OnInit() override;

private:
};
 
wxIMPLEMENT_APP(MyApp);
 
class MyFrame : public wxFrame
{
public:
    MyFrame();
    void OnFrame(int64_t w, int64_t h, std::shared_ptr<privmx::endpoint::stream::Frame> frame, const std::string id);
    void render(wxDC& dc);
private:
    void OnHello(wxCommandEvent& event);
    void OnExit(wxCommandEvent& event);
    void OnAbout(wxCommandEvent& event);
    void OnPaint(wxPaintEvent& event);

    std::mutex m;
    wxBoxSizer* sizer;

    wxPanel* m_board;
    std::vector<unsigned char> picData_vector = std::vector<unsigned char>(4 * MAX_VIDEO_W * MAX_VIDEO_W);
    wxBitmap old_bmp = wxBitmap(MAX_VIDEO_W, MAX_VIDEO_H, 32);
    wxBitmap bmp = wxBitmap(MAX_VIDEO_W, MAX_VIDEO_H, 32);
    int tmp = 0;

    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<stream::StreamApi> streamApi;
};
 
enum
{
    ID_Hello = 1
};
 
bool MyApp::OnInit()
{
    MyFrame *appFrame = new MyFrame();
    appFrame->Show(true);
    return true;
}
 
MyFrame::MyFrame()
    : wxFrame(nullptr, wxID_ANY, "Hello World", wxDefaultPosition, {MAX_VIDEO_W, MAX_VIDEO_H})
{
    m_board = new wxPanel(this, wxID_ANY, wxDefaultPosition, wxSize(MAX_VIDEO_W, MAX_VIDEO_H));
    m_board->SetBackgroundColour(wxColor(100, 100, 200));
    m_board->Bind(wxEVT_PAINT, &MyFrame::OnPaint, this);

    sizer = new wxBoxSizer(wxVERTICAL);
    sizer->Add(m_board, 0, wxEXPAND | wxALL);

    crypto::CryptoApi cryptoApi = crypto::CryptoApi::create();
    connection = std::make_shared<core::Connection>(core::Connection::connect("L3DdgfGagr2yGFEHs1FcRQRGrpa4nwQKdPcfPiHxcDcZeEb3wYaN", "fc47c4e4-e1dc-414a-afa4-71d436398cfc", "http://webrtc2.s24.simplito.com:3000"));
     streamApi = std::make_shared<stream::StreamApi>(stream::StreamApi::create(*connection));
    auto context = connection->listContexts({.skip=0, .limit=1, .sortOrder="asc"}).readItems[0];
    auto streamList = streamApi->listStreamRooms(context.contextId, {.skip=0, .limit=1, .sortOrder="asc"});
    if(streamList.readItems.size()>=1) {
        for(auto a : streamList.readItems) { 
            streamApi->deleteStreamRoom(a.streamRoomId);
        }
    } 
    auto pubKey = cryptoApi.derivePublicKey("L3DdgfGagr2yGFEHs1FcRQRGrpa4nwQKdPcfPiHxcDcZeEb3wYaN");
    std::vector<privmx::endpoint::core::UserWithPubKey> users = {
        privmx::endpoint::core::UserWithPubKey{.userId=context.userId, .pubKey=pubKey}
    };
    std::string streamRoomId = streamApi->createStreamRoom(
        context.contextId,
        users,
        users,
        privmx::endpoint::core::Buffer::from(""),
        privmx::endpoint::core::Buffer::from(""),
        std::nullopt
    );
    
    auto streamId = streamApi->createStream(streamRoomId);
    auto listAudioRecordingDevices = streamApi->listAudioRecordingDevices();
    streamApi->trackAdd(streamId, stream::DeviceType::Audio);
    auto listVideoRecordingDevices = streamApi->listVideoRecordingDevices();
    streamApi->trackAdd(streamId, stream::DeviceType::Video);
    streamApi->publishStream(streamId);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    
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


void MyFrame::OnPaint(wxPaintEvent&)
{

    std::unique_lock<std::mutex> lock(m);
    wxPaintDC dc(m_board);
    dc.Clear();
    if(tmp) {
        dc.DrawBitmap(bmp.GetSubBitmap(wxRect(0, 0, bmp.GetWidth(), bmp.GetHeight())), 0, 0, false);
    }
}

void MyFrame::OnFrame(int64_t w, int64_t h, std::shared_ptr<privmx::endpoint::stream::Frame> frame, const std::string id) {
    if(m_board != NULL) {
        tmp = 1;
        std::cout << w << " - " << h << " frame Size" << std::endl;
        auto board_size = m_board->GetClientSize();
        std::cout << board_size.GetWidth() << " - " << board_size.GetHeight() << " board Size" << std::endl;
        double scaleW = (double)board_size.GetWidth() / w;
        double scaleH = (double)board_size.GetHeight() / h;
        double scale = scaleW < scaleH ? scaleW : scaleH;
        std::cout << scaleW << " - " << scaleH << " board scale" << std::endl;
        int64_t W =  scale * w;
        int64_t H =  scale * h;
        {
            std::unique_lock<std::mutex> lock(m); 
            picData_vector.reserve(4*W*H);
            frame->ConvertToRGBA(&picData_vector[0], 1, W, H);
            bmp = RGBAintoBitmap(W, H, &picData_vector[0]);
        }
        m_board->Refresh();
        // Update();
    } else {
        std::cout << "-------------------------------- NULL --------------------------------" << std::endl;
    }
}
 
void MyFrame::OnExit(wxCommandEvent& event)
{
    Close(true);
}
 
void MyFrame::OnAbout(wxCommandEvent& event)
{
    wxMessageBox("This is a wxWidgets Hello World example",
                 "About Hello World", wxOK | wxICON_INFORMATION);
}
 
void MyFrame::OnHello(wxCommandEvent& event)
{
    wxLogMessage("Hello world from wxWidgets!");
}