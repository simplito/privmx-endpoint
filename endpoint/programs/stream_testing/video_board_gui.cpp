
#include <wx/wx.h>
#include <wx/rawbmp.h>
#include <wx/rawbmp.h>
#include <wx/dcgraph.h>
#include <wx/textentry.h>
#include <wx/glcanvas.h>
#include <wx/statline.h>
#include <wx/odcombo.h>
#include <wx/settings.h>

#include <iostream>
#include <sstream>
#include <string>
#include <fstream>
#include <vector>
#include <thread>
#include <mutex>
#include <map>
#include <set>
#include <algorithm>

#include <privmx/utils/Logger.hpp>
#include <privmx/utils/CancellationToken.hpp>
#include <privmx/endpoint/core/Exception.hpp>

#include <privmx/endpoint/core/Config.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/Events.hpp>
#include <privmx/endpoint/core/EventQueue.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/thread/Events.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>
#include <privmx/endpoint/store/Events.hpp>
#include <privmx/endpoint/stream/StreamApi.hpp>
#include <privmx/endpoint/stream/Events.hpp>
#include <privmx/endpoint/stream/Types.hpp>
#include <privmx/endpoint/stream/webrtc/OnTrackInterface.hpp>
#include <privmx/endpoint/stream/webrtc/Types.hpp>
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
            // std::unique_lock<std::mutex> lock(m);
            tmp_bmp = bmp;
            haveNewFrame = false;
        }
        dc.DrawBitmap(tmp_bmp->GetSubBitmap(wxRect(0, 0, tmp_bmp->GetWidth(), tmp_bmp->GetHeight())), 0, 0, false);
    }
}


// Routes remote tracks/frames from the current StreamApi to the GUI callbacks.
class GuiOnTrack : public privmx::endpoint::stream::OnTrackInterface {
public:
    using OnFrameCallback = std::function<void(int64_t, int64_t, std::shared_ptr<privmx::endpoint::stream::Frame>, const std::string&, const std::vector<std::string>&)>;
    using OnVideoRemoveCallback = std::function<void(const std::string&)>;

    GuiOnTrack(OnFrameCallback onFrame, OnVideoRemoveCallback onVideoRemove)
        : _onFrame(std::move(onFrame)), _onVideoRemove(std::move(onVideoRemove)) {}

    void OnRemoteTrack(privmx::endpoint::stream::Track track, privmx::endpoint::stream::TrackAction action) override {
        if(track.kind == privmx::endpoint::stream::DataType::VIDEO && action == privmx::endpoint::stream::TrackAction::REMOVED) {
            _onVideoRemove(track.trackId);
        }
    }

    void OnData(std::shared_ptr<privmx::endpoint::stream::Data> data) override {
        if(data->type == privmx::endpoint::stream::DataType::VIDEO) {
            auto videoData = std::dynamic_pointer_cast<privmx::endpoint::stream::VideoData>(data);
            if(videoData) {
                _onFrame(videoData->w, videoData->h, videoData->frameData, videoData->track, videoData->streamIds);
            }
        }
    }

private:
    OnFrameCallback _onFrame;
    OnVideoRemoveCallback _onVideoRemove;
};


// Optional values taken from the command line (same order as single_video_receiver)
// used to pre-fill the connection fields in the UI.
struct InitialArgs {
    std::optional<std::string> privKey;
    std::optional<std::string> solutionId;
    std::optional<std::string> bridgeUrl;
    std::optional<std::string> contextId;
    std::optional<std::string> streamRoomId;
};

struct PublishOptions {
    std::optional<stream::AudioDevice>   audio;
    std::optional<stream::VideoDevice>   video;
    std::optional<stream::DesktopDevice> desktop;
};

// Dialog shown before publishing that lets the user pick camera, audio, and/or desktop source.
class PublishOptionsDialog : public wxDialog {
public:
    PublishOptionsDialog(
        wxWindow* parent,
        const std::vector<stream::AudioDevice>&   audioDevices,
        const std::vector<stream::VideoDevice>&   videoDevices,
        const std::vector<stream::DesktopDevice>& screenDevices,
        const std::vector<stream::DesktopDevice>& windowDevices
    ) : wxDialog(parent, wxID_ANY, "Publish options", wxDefaultPosition, wxSize(420, -1)),
        _audioDevices(audioDevices), _videoDevices(videoDevices),
        _screenDevices(screenDevices), _windowDevices(windowDevices)
    {
        wxArrayString audioChoices, videoChoices, desktopChoices;
        audioChoices.Add("None");
        for(const auto& d : audioDevices)  audioChoices.Add(d.name);
        videoChoices.Add("None");
        for(const auto& d : videoDevices)  videoChoices.Add(d.name);
        desktopChoices.Add("None");
        for(const auto& d : screenDevices) desktopChoices.Add("Screen: " + d.name);
        for(const auto& d : windowDevices) desktopChoices.Add("Window: " + d.name);

        _audioChoice   = new wxChoice(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, audioChoices);
        _videoChoice   = new wxChoice(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, videoChoices);
        _desktopChoice = new wxChoice(this, wxID_ANY, wxDefaultPosition, wxDefaultSize, desktopChoices);

        // Default: select first available device for audio and video, none for desktop.
        _audioChoice->SetSelection(audioDevices.empty()  ? 0 : 1);
        _videoChoice->SetSelection(videoDevices.empty()  ? 0 : 1);
        _desktopChoice->SetSelection(0);

        auto* grid = new wxFlexGridSizer(2, 5, 5);
        grid->AddGrowableCol(1, 1);
        grid->Add(new wxStaticText(this, wxID_ANY, "Camera"),  0, wxALIGN_CENTER_VERTICAL);
        grid->Add(_videoChoice,   1, wxEXPAND);
        grid->Add(new wxStaticText(this, wxID_ANY, "Audio"),   0, wxALIGN_CENTER_VERTICAL);
        grid->Add(_audioChoice,   1, wxEXPAND);
        grid->Add(new wxStaticText(this, wxID_ANY, "Desktop"), 0, wxALIGN_CENTER_VERTICAL);
        grid->Add(_desktopChoice, 1, wxEXPAND);

        auto* sizer = new wxBoxSizer(wxVERTICAL);
        sizer->Add(grid, 0, wxEXPAND | wxALL, 10);
        sizer->Add(CreateButtonSizer(wxOK | wxCANCEL), 0, wxEXPAND | wxALL, 5);
        SetSizerAndFit(sizer);
    }

    PublishOptions GetOptions() const {
        PublishOptions opts;
        int audioSel = _audioChoice->GetSelection();
        if(audioSel > 0 && audioSel - 1 < (int)_audioDevices.size())
            opts.audio = _audioDevices[audioSel - 1];

        int videoSel = _videoChoice->GetSelection();
        if(videoSel > 0 && videoSel - 1 < (int)_videoDevices.size())
            opts.video = _videoDevices[videoSel - 1];

        int deskSel = _desktopChoice->GetSelection();
        if(deskSel > 0) {
            int idx = deskSel - 1;
            if(idx < (int)_screenDevices.size())
                opts.desktop = _screenDevices[idx];
            else if(idx - (int)_screenDevices.size() < (int)_windowDevices.size())
                opts.desktop = _windowDevices[idx - (int)_screenDevices.size()];
        }
        return opts;
    }

private:
    wxChoice* _audioChoice;
    wxChoice* _videoChoice;
    wxChoice* _desktopChoice;
    std::vector<stream::AudioDevice>   _audioDevices;
    std::vector<stream::VideoDevice>   _videoDevices;
    std::vector<stream::DesktopDevice> _screenDevices;
    std::vector<stream::DesktopDevice> _windowDevices;
};


// Stream-room picker that paints rooms by their state: created -> green, open -> blue,
// closed -> red (with a "(closed)" suffix so it is obvious which rooms can no longer be
// joined). States are kept in sync with the item list through ClearRooms()/AppendRoom()
// instead of plain Clear()/Append().
class StreamRoomComboBox : public wxOwnerDrawnComboBox {
public:
    StreamRoomComboBox(wxWindow* parent)
        : wxOwnerDrawnComboBox(parent, wxID_ANY, "", wxDefaultPosition, wxDefaultSize, wxArrayString(), 0) {}

    void ClearRooms() {
        Clear();
        _states.clear();
    }

    void AppendRoom(const wxString& streamRoomId, const wxString& state) {
        Append(streamRoomId);
        _states.push_back(state);
    }

    // True only for a listed room known to be closed; ids typed by hand (not in the list) are
    // treated as open, since we have no state for them.
    bool isRoomClosed(const wxString& streamRoomId) const {
        int idx = FindString(streamRoomId);
        if(idx == wxNOT_FOUND || idx >= (int)_states.size()) return false;
        return _states[idx] == "closed";
    }

protected:
    // created -> green, open -> blue, closed -> red; unknown/typed ids fall back to the system
    // colours (honouring the selection highlight so they stay readable).
    static wxColour colourForState(const wxString& state, bool selected) {
        if(state == "created") return wxColour(0, 128, 0); // dark green, readable on white
        if(state == "open")    return *wxBLUE;
        if(state == "closed")  return *wxRED;
        return selected
            ? wxSystemSettings::GetColour(wxSYS_COLOUR_HIGHLIGHTTEXT)
            : wxSystemSettings::GetColour(wxSYS_COLOUR_WINDOWTEXT);
    }

    void OnDrawItem(wxDC& dc, const wxRect& rect, int item, int flags) const override {
        if(item == wxNOT_FOUND) return;
        wxString state = item < (int)_states.size() ? _states[item] : wxString();
        bool selected = (flags & wxODCB_PAINTING_SELECTED) != 0;
        dc.SetTextForeground(colourForState(state, selected));
        wxString text = GetString(item);
        if(state == "closed") text += "  (closed)";
        dc.DrawText(text, rect.x + 3, rect.y + (rect.height - dc.GetCharHeight()) / 2);
    }

    wxCoord OnMeasureItem(size_t) const override { return 22; }

private:
    std::vector<wxString> _states; // parallel to the combo items ("created" | "open" | "closed")
};


class MyFrame : public wxFrame
{
public:
    MyFrame(const InitialArgs& initialArgs = InitialArgs{});
    void Connect(std::string privKey, std::string solutionId, std::string bridgeUrl, std::string contextId);
    void PublishToStreamRoom(std::string streamRoomId, const PublishOptions& opts);
    void JoinToStreamRoom(std::string streamRoomId);
    void CreateRoomForContext(std::string contextId);
    void RefreshStreamRoomList(std::string contextId);
    std::vector<privmx::endpoint::stream::StreamRoom> ListStreamRooms(std::string streamRoomId);
private:
    void OnFrame(int64_t w, int64_t h, std::shared_ptr<privmx::endpoint::stream::Frame> frame, const std::string& id, const std::vector<std::string>& streamIds);
    void OnVideoRemove(const std::string& id);
    void OnStreamUnpublished(int64_t streamId);
    void SubscribeToRemoteStreams(const std::string& streamRoomId, const std::vector<stream::StreamSubscription>& subscriptions);
    void OnResize(wxSizeEvent& event);
    void OnExit(wxCloseEvent& event);
    // tints the room field red while the selected/typed room is a closed (non-joinable) one
    void UpdateRoomValueColour();

    privmx::utils::CancellationToken cancellationToken;
    std::mutex m;
    std::shared_mutex _videoPanels;
    wxGridSizer* sizer;
    std::map<std::string, std::shared_ptr<VideoPanel>> mapOfVideoPanels;

    wxPanel* m_board;


    wxButton* connectButton;
    wxButton* joinButton;
    wxButton* publishButton;
    wxButton* createRoomButton;
    wxTextCtrl* privKeyInput;
    wxTextCtrl* solutionIdInput;
    wxTextCtrl* bridgeUrlInput;
    wxTextCtrl* contextIdInput;
    StreamRoomComboBox* streamRoomIdInput;
    wxCheckBox* hideBrokenFrames;


    std::vector<unsigned char> picData_vector = std::vector<unsigned char>(4 * MAX_VIDEO_W * MAX_VIDEO_W);
    wxBitmap bmp = wxBitmap(MAX_VIDEO_W, MAX_VIDEO_H, 32);
    int tmp = 0;
    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<event::EventApi> eventApi;
    std::shared_ptr<stream::StreamApi> streamApi;
    std::thread _event_handler;
    std::optional<std::string> joinedStreamRoomId;
    std::optional<stream::SubscriberStreamHandle> subscriberStreamHandle;
    std::optional<int64_t> publishedStream;
    std::shared_ptr<GuiOnTrack> _onTrack;
    // Coalesces incoming frames per video id so we never flood the GUI event queue:
    // a new frame for an id is dropped while a render for that id is still pending.
    std::mutex _pendingFramesMutex;
    std::set<std::string> _pendingFrames;
    // panel id (webrtc track id) -> the webrtc stream ids it belongs to.
    // The webrtc stream id equals the bridge streamId rendered as a string, so this lets us
    // remove the right panels when a streamUnpublished event arrives. GUI-thread only.
    std::map<std::string, std::vector<std::string>> _panelStreamIds;
};


 
bool MyApp::OnInit()
{
    // Optional CLI args (same order as single_video_receiver): PrivKey SolutionId BridgeUrl ContextId [StreamRoomId]
    InitialArgs initialArgs;
    if(this->argc > 1) initialArgs.privKey = this->argv[1].ToStdString();
    if(this->argc > 2) initialArgs.solutionId = this->argv[2].ToStdString();
    if(this->argc > 3) initialArgs.bridgeUrl = this->argv[3].ToStdString();
    if(this->argc > 4) initialArgs.contextId = this->argv[4].ToStdString();
    if(this->argc > 5) initialArgs.streamRoomId = this->argv[5].ToStdString();

    MyFrame *appFrame = new MyFrame(initialArgs);
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
        // OnResize runs on the GUI thread, so refreshing the panels here is safe.
        std::for_each(mapOfVideoPanels.begin(), mapOfVideoPanels.end(), [&](const auto& p) {
            if(p.second != nullptr) p.second->Refresh();
        });
    }
    event.Skip();
}

void MyFrame::OnExit(wxCloseEvent& event) {
    cancellationToken.cancel();
    if(streamApi) {
        if(joinedStreamRoomId.has_value()) {
            if(publishedStream.has_value()) {
                LOG_INFO("StreamProgram wx: OnExit Unpublishing Stream")
                streamApi->removeStream(publishedStream.value());
            }
            if(subscriberStreamHandle.has_value()) {
                LOG_INFO("StreamProgram wx: OnExit Leaving Stream")
                streamApi->removeSubscriberStream(subscriberStreamHandle.value());
            }
            streamApi->leaveStreamRoom(joinedStreamRoomId.value());
        }
        streamApi.reset();
        LOG_INFO("StreamProgram wx: OnExit Join threads")
        if(_event_handler.joinable()) {
            _event_handler.join();
        }
    }
    if(eventApi) eventApi.reset();
    if(connection) {
        LOG_INFO("StreamProgram wx: OnExit Disconnecting")
        connection->disconnect();
        connection.reset();
    }
    privmx::endpoint::core::EventQueue::getInstance().emitBreakEvent();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    LOG_INFO("StreamProgram wx: OnExit Closed")
    Destroy();
}

MyFrame::MyFrame(const InitialArgs& initialArgs)
    : wxFrame(nullptr, wxID_ANY, "Video Board", wxDefaultPosition, wxDefaultSize), cancellationToken(privmx::utils::CancellationToken())
{
    m_board = new wxPanel(this, wxID_ANY);

    // --- create controls ---
    connectButton = new wxButton(this->m_board, wxID_ANY, "Connect");
    joinButton = new wxButton(this->m_board, wxID_ANY, "Join");
    publishButton = new wxButton(this->m_board, wxID_ANY, "Publish");
    createRoomButton = new wxButton(this->m_board, wxID_ANY, "Create room (all context users as managers)");
    // These actions require an active connection; unlocked after a successful Connect.
    joinButton->Disable();
    publishButton->Disable();
    createRoomButton->Disable();

    privKeyInput      = new wxTextCtrl(this->m_board, wxID_ANY, "");
    solutionIdInput   = new wxTextCtrl(this->m_board, wxID_ANY, "");
    bridgeUrlInput    = new wxTextCtrl(this->m_board, wxID_ANY, "");
    contextIdInput    = new wxTextCtrl(this->m_board, wxID_ANY, "");
    streamRoomIdInput = new StreamRoomComboBox(this->m_board); // filled with the 20 newest rooms after connect
    // Grey placeholder hints (shown only while empty; never become the value).
    privKeyInput->SetHint("private key");
    solutionIdInput->SetHint("solution id");
    bridgeUrlInput->SetHint("bridge url");
    contextIdInput->SetHint("context id");
    streamRoomIdInput->SetHint("stream room id");

    hideBrokenFrames = new wxCheckBox(this->m_board, wxID_ANY, "hide broken frames");
    hideBrokenFrames->SetValue(true);

    // Pre-fill connection fields from CLI args when provided.
    if(initialArgs.privKey)      privKeyInput->SetValue(*initialArgs.privKey);
    if(initialArgs.solutionId)   solutionIdInput->SetValue(*initialArgs.solutionId);
    if(initialArgs.bridgeUrl)    bridgeUrlInput->SetValue(*initialArgs.bridgeUrl);
    if(initialArgs.contextId)    contextIdInput->SetValue(*initialArgs.contextId);
    if(initialArgs.streamRoomId) streamRoomIdInput->SetValue(*initialArgs.streamRoomId);

    // --- layout: a single labelled column, grouped into sections ---
    auto* boardSizer = new wxBoxSizer(wxVERTICAL);

    boardSizer->Add(new wxStaticText(m_board, wxID_ANY, "Connection"), 0, wxLEFT | wxTOP, 5);
    auto* connFields = new wxFlexGridSizer(2, 5, 5); // 2 columns, vertical gap, horizontal gap
    connFields->AddGrowableCol(1, 1);
    connFields->Add(new wxStaticText(m_board, wxID_ANY, "Private key"), 0, wxALIGN_CENTER_VERTICAL);
    connFields->Add(privKeyInput, 1, wxEXPAND);
    connFields->Add(new wxStaticText(m_board, wxID_ANY, "Solution id"), 0, wxALIGN_CENTER_VERTICAL);
    connFields->Add(solutionIdInput, 1, wxEXPAND);
    connFields->Add(new wxStaticText(m_board, wxID_ANY, "Bridge url"), 0, wxALIGN_CENTER_VERTICAL);
    connFields->Add(bridgeUrlInput, 1, wxEXPAND);
    connFields->Add(new wxStaticText(m_board, wxID_ANY, "Context id"), 0, wxALIGN_CENTER_VERTICAL);
    connFields->Add(contextIdInput, 1, wxEXPAND);
    boardSizer->Add(connFields, 0, wxEXPAND | wxALL, 5);
    boardSizer->Add(connectButton, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 5);

    boardSizer->Add(new wxStaticLine(m_board), 0, wxEXPAND | wxALL, 5);

    boardSizer->Add(new wxStaticText(m_board, wxID_ANY, "Stream room"), 0, wxLEFT | wxTOP, 5);
    boardSizer->Add(createRoomButton, 0, wxEXPAND | wxALL, 5);
    auto* roomRow = new wxBoxSizer(wxHORIZONTAL);
    roomRow->Add(new wxStaticText(m_board, wxID_ANY, "Room"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 5);
    roomRow->Add(streamRoomIdInput, 1, wxEXPAND);
    boardSizer->Add(roomRow, 0, wxEXPAND | wxLEFT | wxRIGHT, 5);
    auto* roomButtons = new wxBoxSizer(wxHORIZONTAL);
    roomButtons->Add(joinButton, 1, wxEXPAND | wxRIGHT, 5);
    roomButtons->Add(publishButton, 1, wxEXPAND);
    boardSizer->Add(roomButtons, 0, wxEXPAND | wxALL, 5);

    boardSizer->Add(new wxStaticLine(m_board), 0, wxEXPAND | wxALL, 5);

    boardSizer->Add(new wxStaticText(m_board, wxID_ANY, "Options"), 0, wxLEFT | wxTOP, 5);
    boardSizer->Add(hideBrokenFrames, 0, wxALL, 5);

    this->hideBrokenFrames->Bind(wxEVT_CHECKBOX, [&](wxCommandEvent& event) {
        try {
            if(streamApi != nullptr && joinedStreamRoomId.has_value()) {
                streamApi->dropBrokenFrames(joinedStreamRoomId.value(), hideBrokenFrames->GetValue());
                return;
            } 
            hideBrokenFrames->SetValue(true);
        } catch (const privmx::endpoint::core::Exception& e) {
            hideBrokenFrames->SetValue(true);
        };
    });

    m_board->SetSizerAndFit(boardSizer);


    this->connectButton->Bind(wxEVT_BUTTON, [&](wxCommandEvent& event) {
        try {
            Connect(
                privKeyInput->GetValue().ToStdString(),
                solutionIdInput->GetValue().ToStdString(),
                bridgeUrlInput->GetValue().ToStdString(),
                contextIdInput->GetValue().ToStdString()
            );
        } catch (const privmx::endpoint::core::Exception& e) {

        };
    });

    this->joinButton->Bind(wxEVT_BUTTON, [&](wxCommandEvent& event) {
        try {
            if(streamApi == nullptr) return;
            if(streamRoomIdInput->isRoomClosed(streamRoomIdInput->GetValue())) {
                LOG_INFO("StreamProgram wx: Join Stream room is closed - cannot join")
                wxMessageBox("This stream room is closed and cannot be joined.", "Closed room", wxOK | wxICON_WARNING, this);
                return;
            }
            JoinToStreamRoom(streamRoomIdInput->GetValue().ToStdString());
        } catch (const privmx::endpoint::core::Exception& e) {

        };
    });
    this->publishButton->Bind(wxEVT_BUTTON, [&](wxCommandEvent& event) {
        try {
            if(streamApi == nullptr) return;
            if(streamRoomIdInput->isRoomClosed(streamRoomIdInput->GetValue())) {
                LOG_INFO("StreamProgram wx: Publish Stream room is closed - cannot publish")
                wxMessageBox("This stream room is closed and cannot be joined.", "Closed room", wxOK | wxICON_WARNING, this);
                return;
            }
            auto audioDevices   = streamApi->getAudioDevices();
            auto videoDevices   = streamApi->getVideoDevices();
            auto screenDevices  = streamApi->getDesktopDevices(stream::DesktopType::Screen);
            auto windowDevices  = streamApi->getDesktopDevices(stream::DesktopType::Window);
            PublishOptionsDialog dlg(this, audioDevices, videoDevices, screenDevices, windowDevices);
            if(dlg.ShowModal() != wxID_OK) return;
            PublishToStreamRoom(streamRoomIdInput->GetValue().ToStdString(), dlg.GetOptions());
        } catch (const privmx::endpoint::core::Exception& e) {

        };
    });
    this->createRoomButton->Bind(wxEVT_BUTTON, [&](wxCommandEvent& event) {
        try {
            if(streamApi == nullptr) return;
            CreateRoomForContext(contextIdInput->GetValue().ToStdString());
        } catch (const privmx::endpoint::core::Exception& e) {

        };
    });

    // keep the room field red while the selected/typed room is a closed (non-joinable) one
    this->streamRoomIdInput->Bind(wxEVT_COMBOBOX, [&](wxCommandEvent& event) { UpdateRoomValueColour(); event.Skip(); });
    this->streamRoomIdInput->Bind(wxEVT_TEXT, [&](wxCommandEvent& event) { UpdateRoomValueColour(); event.Skip(); });

    sizer = new wxGridSizer(2); // grid of remote video tiles
    this->Bind(wxEVT_SIZE, &MyFrame::OnResize , this);
    this->Bind(wxEVT_CLOSE_WINDOW, &MyFrame::OnExit , this);

    // Controls on the left, video tiles on the right.
    auto* topSizer = new wxBoxSizer(wxHORIZONTAL);
    topSizer->Add(m_board, 0, wxEXPAND | wxALL, 5);
    topSizer->Add(sizer, 1, wxEXPAND | wxALL, 5);
    this->SetSizerAndFit(topSizer);


    _onTrack = std::make_shared<GuiOnTrack>(
        std::bind(&MyFrame::OnFrame, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5),
        std::bind(&MyFrame::OnVideoRemove, this, std::placeholders::_1)
    );

    _event_handler = std::thread([&]() {
        auto eventQueue = privmx::endpoint::core::EventQueue::getInstance();
        while (!cancellationToken.isCancelled()) {
            auto eventHolder = eventQueue.waitEvent();
            if(privmx::endpoint::core::Events::isLibBreakEvent(eventHolder)) {
                return;
            }
            LOG_INFO("StreamProgram wx: Event recived : ", eventHolder.toJSON())
            LOG_INFO("StreamProgram wx: Event recived type : ", eventHolder.type())
            if(privmx::endpoint::stream::Events::isStreamPublishedEvent(eventHolder)) {
                LOG_INFO("StreamProgram wx: isStreamPublishedEvent")
                auto eventData = privmx::endpoint::stream::Events::extractStreamPublishedEvent(eventHolder);

                if(streamApi && joinedStreamRoomId.has_value() && joinedStreamRoomId.value() == eventData.data.streamRoomId) {
                    std::vector<stream::StreamSubscription> streamSubscription;
                    streamSubscription.push_back(stream::StreamSubscription{eventData.data.stream.id, std::nullopt});
                    SubscribeToRemoteStreams(eventData.data.streamRoomId, streamSubscription);
                }
            } else if (privmx::endpoint::stream::Events::isStreamUnpublishedEvent(eventHolder)) {
                LOG_INFO("StreamProgram wx: isStreamUnpublishedEvent")
                auto eventData = privmx::endpoint::stream::Events::extractStreamUnpublishedEvent(eventHolder);
            }
        }
    });
}

void MyFrame::Connect(std::string privKey, std::string solutionId, std::string bridgeUrl, std::string contextId) {
    std::cout << "connecting with privKey: " << privKey << " solutionId: " << solutionId
              << " bridgeUrl: " << bridgeUrl << " contextId: " << contextId << std::endl;
    try {
        connection = std::make_shared<core::Connection>(core::Connection::connect(privKey, solutionId, bridgeUrl));
        eventApi = std::make_shared<event::EventApi>(event::EventApi::create(*connection));
        streamApi = std::make_shared<stream::StreamApi>(stream::StreamApi::create(*connection, *eventApi));
    } catch (const privmx::endpoint::core::Exception& e) {
        LOG_INFO("StreamProgram wx: Connect Connection to bridge failed")
        return;
    }
    streamApi->subscribeFor({
        streamApi->buildSubscriptionQuery(stream::EventType::STREAMROOM_JOIN, stream::EventSelectorType::CONTEXT_ID, contextId),
        streamApi->buildSubscriptionQuery(stream::EventType::STREAMROOM_LEAVE, stream::EventSelectorType::CONTEXT_ID, contextId),
        streamApi->buildSubscriptionQuery(stream::EventType::STREAM_PUBLISH, stream::EventSelectorType::CONTEXT_ID, contextId),
        streamApi->buildSubscriptionQuery(stream::EventType::STREAM_UNPUBLISH, stream::EventSelectorType::CONTEXT_ID, contextId),
        streamApi->buildSubscriptionQuery(stream::EventType::STREAMROOM_CREATE, stream::EventSelectorType::CONTEXT_ID, contextId),
        streamApi->buildSubscriptionQuery(stream::EventType::STREAMROOM_DELETE, stream::EventSelectorType::CONTEXT_ID, contextId),
        streamApi->buildSubscriptionQuery(stream::EventType::STREAMROOM_UPDATE, stream::EventSelectorType::CONTEXT_ID, contextId)
    });

    // connected: room creation, join and publish are now available
    joinButton->Enable();
    publishButton->Enable();
    createRoomButton->Enable();
    RefreshStreamRoomList(contextId);
}

void MyFrame::CreateRoomForContext(std::string contextId) {
    if(streamApi == nullptr || connection == nullptr) return;
    // Gather every user in the context and make them all users AND managers of the new room.
    std::vector<privmx::endpoint::core::UserWithPubKey> users;
    auto usersList = connection->listContextUsers(contextId, core::PagingQuery{.skip=0, .limit=100, .sortOrder="desc"});
    for(const auto& userInfo : usersList.readItems) {
        users.push_back(userInfo.user);
    }
    LOG_INFO("StreamProgram wx: CreateRoomForContext Context users: " + std::to_string(users.size()));
    auto streamRoomId = streamApi->createStreamRoom(
        contextId,
        users,
        users,
        core::Buffer::from("publicMeta"),
        core::Buffer::from("privateMeta"),
        std::nullopt
    );
    LOG_INFO("StreamProgram wx: CreateRoomForContext Created streamRoomId: " + streamRoomId);
    RefreshStreamRoomList(contextId);
    streamRoomIdInput->SetValue(streamRoomId);
}

void MyFrame::PublishToStreamRoom(std::string streamRoomId, const PublishOptions& opts) {
    if(publishedStream.has_value()) {
        LOG_INFO("StreamProgram wx: PublishToStreamRoom Unpublishing Stream")
        streamApi->removeStream(publishedStream.value());
    }
    if(!joinedStreamRoomId.has_value()) {
        streamApi->joinStreamRoom(streamRoomId);
        streamApi->addRemoteStreamListener(streamRoomId, std::nullopt, _onTrack);
        joinedStreamRoomId = streamRoomId;
    }
    auto streamHandle = streamApi->createStream(streamRoomId);
    publishedStream = streamHandle;
    if(opts.video)   streamApi->addTrack(streamHandle, *opts.video,   stream::MediaTrackConstrains{});
    if(opts.audio)   streamApi->addTrack(streamHandle, *opts.audio,   stream::MediaTrackConstrains{});
    if(opts.desktop) streamApi->addTrack(streamHandle, *opts.desktop, stream::MediaTrackConstrains{});
    streamApi->publishStream(streamHandle);
}

void MyFrame::JoinToStreamRoom(std::string streamRoomId) {
    if(!joinedStreamRoomId.has_value()) {
        streamApi->joinStreamRoom(streamRoomId);
        streamApi->addRemoteStreamListener(streamRoomId, std::nullopt, _onTrack);
        joinedStreamRoomId = streamRoomId;
    }
    LOG_INFO("StreamProgram wx: JoinToStreamRoom streamApi->listStreams StreamRoomId: " + streamRoomId);
    auto streamlist = streamApi->listStreams(streamRoomId);
    LOG_INFO("StreamProgram wx: JoinToStreamRoom streamApi->listStreams.size(): " + std::to_string(streamlist.size()));

    std::vector<stream::StreamSubscription> streamSubscription;
    if(streamlist.size() == 0) return;
    for(int i = 0; i < streamlist.size(); i++) {
        LOG_INFO("StreamProgram wx: JoinToStreamRoom Stream Id: " + std::to_string(streamlist[i].id));
        streamSubscription.push_back(stream::StreamSubscription{streamlist[i].id, std::nullopt});
    }
    SubscribeToRemoteStreams(streamRoomId, streamSubscription);
    joinedStreamRoomId = streamRoomId;
}

void MyFrame::SubscribeToRemoteStreams(const std::string& streamRoomId, const std::vector<stream::StreamSubscription>& subscriptions) {
    if(subscriptions.empty()) return;
    if(subscriberStreamHandle.has_value()) {
        // grow the existing subscriber stream with the new subscriptions
        streamApi->updateSubscriberStream(subscriberStreamHandle.value(), subscriptions, {});
    } else {
        subscriberStreamHandle = streamApi->createSubscriberStream(streamRoomId, subscriptions);
    }
}

std::vector<privmx::endpoint::stream::StreamRoom> MyFrame::ListStreamRooms(std::string contextId) {
    auto streamlist = streamApi->listStreamRooms(contextId, core::PagingQuery{.skip=0, .limit=20, .sortOrder="desc"});
    return streamlist.readItems;
}

void MyFrame::RefreshStreamRoomList(std::string contextId) {
    if(streamApi == nullptr) return;
    auto rooms = ListStreamRooms(contextId); // 20 newest, newest first
    wxString previous = streamRoomIdInput->GetValue();
    streamRoomIdInput->ClearRooms();
    for(const auto& room : rooms) {
        streamRoomIdInput->AppendRoom(room.streamRoomId, room.state); // coloured by state: created/open/closed
    }
    // keep the previously typed/selected room if still present, otherwise pick the newest
    if(!previous.IsEmpty() && streamRoomIdInput->FindString(previous) != wxNOT_FOUND) {
        streamRoomIdInput->SetValue(previous);
    } else if(!rooms.empty()) {
        streamRoomIdInput->SetValue(rooms.front().streamRoomId);
    }
    UpdateRoomValueColour();
}

void MyFrame::UpdateRoomValueColour() {
    if(streamRoomIdInput == nullptr) return;
    bool closed = streamRoomIdInput->isRoomClosed(streamRoomIdInput->GetValue());
    if(wxTextCtrl* textCtrl = streamRoomIdInput->GetTextCtrl()) {
        textCtrl->SetForegroundColour(closed ? *wxRED : wxSystemSettings::GetColour(wxSYS_COLOUR_WINDOWTEXT));
        textCtrl->Refresh();
    }
}

void MyFrame::OnFrame(int64_t w, int64_t h, std::shared_ptr<privmx::endpoint::stream::Frame> frame, const std::string& id, const std::vector<std::string>& streamIds) {
    // Called on a webrtc media thread. All GTK/wx widget access must happen on the GUI
    // thread, so the actual work is marshalled there via CallAfter. To avoid flooding the
    // GUI event queue we drop frames for an id while a render for that id is still pending.
    {
        std::lock_guard<std::mutex> lock(_pendingFramesMutex);
        if(!_pendingFrames.insert(id).second) {
            return;
        }
    }
    CallAfter([this, w, h, frame, id, streamIds]() {
        {
            std::lock_guard<std::mutex> lock(_pendingFramesMutex);
            _pendingFrames.erase(id);
        }
        std::shared_ptr<VideoPanel> videoPanel;
        {
            std::unique_lock<std::shared_mutex> lock(_videoPanels);
            auto it = mapOfVideoPanels.find(id);
            if (it == mapOfVideoPanels.end()) {
                //add video panel
                LOG_INFO("StreamProgram wx: Adding New VideoPanel , Frame id: " + id)
                videoPanel = std::make_shared<VideoPanel>(this);
                mapOfVideoPanels[id] = videoPanel;
                _panelStreamIds[id] = streamIds; // remember which stream this panel belongs to
                sizer->Add(videoPanel.get(), 1, wxEXPAND | wxALL,5);
                Layout();
            } else {
                videoPanel = it->second;
            }
        }
        if(videoPanel != nullptr) {
            videoPanel->Render(w,h,frame);
            videoPanel->Refresh();
        }
    });
}

void MyFrame::OnStreamUnpublished(int64_t streamId) {
    // Remove every panel that belongs to the unpublished stream. The webrtc stream id stored
    // for each panel is the bridge streamId rendered as a string.
    std::string streamIdStr = std::to_string(streamId);
    CallAfter([this, streamIdStr]() {
        std::unique_lock<std::shared_mutex> lock(_videoPanels);
        for(auto it = _panelStreamIds.begin(); it != _panelStreamIds.end(); ) {
            bool belongsToStream = std::find(it->second.begin(), it->second.end(), streamIdStr) != it->second.end();
            if(belongsToStream) {
                LOG_INFO("StreamProgram wx: OnStreamUnpublished Removing panel for stream " + streamIdStr + ", id: " + it->first)
                mapOfVideoPanels.erase(it->first); // drops shared_ptr -> deletes VideoPanel (auto-detaches from sizer)
                it = _panelStreamIds.erase(it);
            } else {
                ++it;
            }
        }
        Layout();
    });
}

void MyFrame::OnVideoRemove(const std::string& id) {
    // Called on a webrtc media thread; marshal the widget removal to the GUI thread.
    CallAfter([this, id]() {
        LOG_INFO("StreamProgram wx: RemovingVideoPanel VideoPanel, id: " + id)
        std::unique_lock<std::shared_mutex> lock(_videoPanels);
        auto it = mapOfVideoPanels.find(id);
        if (it != mapOfVideoPanels.end()) {
            // Erasing drops the shared_ptr, which deletes the VideoPanel; ~wxWindow
            // auto-removes it from the sizer, so Layout() afterwards is safe.
            mapOfVideoPanels.erase(it);
            _panelStreamIds.erase(id);
            Layout();
        }
    });
}
 
