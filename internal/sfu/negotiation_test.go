package sfu

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/webrtc/v4"
)

// negotiationRig is one SFU-side peer with a real PeerConnection, a websocket whose outgoing
// messages the test can read, and a "browser" PeerConnection standing in for the client.
type negotiationRig struct {
	s      *Server
	room   *room
	peer   *peer
	client *webrtc.PeerConnection
	sent   chan signalMessage
}

func newNegotiationRig(t *testing.T) *negotiationRig {
	t.Helper()
	sent := make(chan signalMessage, 32)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			_, raw, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var msg signalMessage
			if json.Unmarshal(raw, &msg) == nil {
				sent <- msg
			}
		}
	}))
	t.Cleanup(server.Close)

	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	api := webrtc.NewAPI()
	serverPC, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { serverPC.Close() })
	clientPC, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clientPC.Close() })

	s := &Server{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	r := &room{SessionID: "session", Peers: map[string]*peer{}, Tracks: map[string]*roomTrack{}}
	p := &peer{UserID: "u1", SessionID: "session", WS: conn, PC: serverPC, WriteTimeout: time.Second}
	return &negotiationRig{s: s, room: r, peer: p, client: clientPC, sent: sent}
}

func (rig *negotiationRig) next(t *testing.T, want string) signalMessage {
	t.Helper()
	select {
	case msg := <-rig.sent:
		if msg.Type != want {
			t.Fatalf("expected a %q message, got %q", want, msg.Type)
		}
		return msg
	case <-time.After(2 * time.Second):
		t.Fatalf("no %q message arrived", want)
		return signalMessage{}
	}
}

func (rig *negotiationRig) expectNothing(t *testing.T) {
	t.Helper()
	select {
	case msg := <-rig.sent:
		t.Fatalf("expected no message, got %q", msg.Type)
	case <-time.After(150 * time.Millisecond):
	}
}

// addForwardedTrack puts a track on the SFU peer's connection the way fan-out does.
func (rig *negotiationRig) addForwardedTrack(t *testing.T, id string) {
	t.Helper()
	track, err := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus}, id, "pufferblow")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rig.peer.PC.AddTrack(track); err != nil {
		t.Fatal(err)
	}
}

// clientOffer is what the browser sends first: an offer carrying its microphone.
func (rig *negotiationRig) clientOffer(t *testing.T) *webrtc.SessionDescription {
	t.Helper()
	if _, err := rig.client.AddTransceiverFromKind(webrtc.RTPCodecTypeAudio); err != nil {
		t.Fatal(err)
	}
	offer, err := rig.client.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := rig.client.SetLocalDescription(offer); err != nil {
		t.Fatal(err)
	}
	return &offer
}

func TestNegotiateWaitsForTheClientsFirstOffer(t *testing.T) {
	rig := newNegotiationRig(t)
	rig.addForwardedTrack(t, "alice")

	if err := rig.s.negotiate(rig.peer); err != nil {
		t.Fatal(err)
	}
	rig.expectNothing(t) // the client has not offered yet, so the SFU must not
	if !rig.peer.renegotiate {
		t.Fatal("the pending track should be remembered for the next round")
	}

	// Once the client's offer is answered, the waiting track is offered.
	rig.s.handleOffer(rig.room, rig.peer, rig.clientOffer(t))
	rig.next(t, "answer")
	offer := rig.next(t, "offer")
	if offer.Offer == nil || !strings.Contains(offer.Offer.SDP, "alice") {
		t.Fatal("the SFU's offer should carry the track that was waiting")
	}
}

func TestNegotiateSendsOneOfferAtATime(t *testing.T) {
	rig := newNegotiationRig(t)
	rig.s.handleOffer(rig.room, rig.peer, rig.clientOffer(t))
	rig.next(t, "answer")

	rig.addForwardedTrack(t, "alice")
	rig.addForwardedTrack(t, "carol")
	if err := rig.s.negotiate(rig.peer); err != nil {
		t.Fatal(err)
	}
	rig.next(t, "offer")

	// A second track arriving while that offer is unanswered waits instead of sending a clashing offer.
	if err := rig.s.negotiate(rig.peer); err != nil {
		t.Fatal(err)
	}
	rig.expectNothing(t)
	if !rig.peer.renegotiate {
		t.Fatal("the second request should be remembered")
	}
}

func TestClientOfferIsDroppedQuietlyWhileOursIsUnanswered(t *testing.T) {
	rig := newNegotiationRig(t)
	rig.s.handleOffer(rig.room, rig.peer, rig.clientOffer(t))
	rig.next(t, "answer")
	rig.addForwardedTrack(t, "alice")
	if err := rig.s.negotiate(rig.peer); err != nil {
		t.Fatal(err)
	}
	rig.next(t, "offer")

	other, err := webrtc.NewAPI().NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.AddTransceiverFromKind(webrtc.RTPCodecTypeAudio); err != nil {
		t.Fatal(err)
	}
	clash, _ := other.CreateOffer(nil)

	rig.s.handleOffer(rig.room, rig.peer, &clash)
	rig.expectNothing(t) // no answer and, above all, no error frame (the client treats those as fatal)
}

func TestCandidatesBeforeTheOfferWaitAndAreAppliedAfter(t *testing.T) {
	rig := newNegotiationRig(t)
	early := &webrtc.ICECandidateInit{Candidate: "candidate:1 1 udp 2130706431 127.0.0.1 50000 typ host"}

	rig.s.handleCandidate(rig.peer, early)
	rig.expectNothing(t) // not an error, however early it is
	if len(rig.peer.pendingCandidates) != 1 {
		t.Fatalf("expected the candidate to be held, have %d", len(rig.peer.pendingCandidates))
	}

	rig.s.handleOffer(rig.room, rig.peer, rig.clientOffer(t))
	rig.next(t, "answer")
	if len(rig.peer.pendingCandidates) != 0 {
		t.Fatal("held candidates should be applied once the offer is in")
	}
}

func TestHeldCandidatesAreCapped(t *testing.T) {
	rig := newNegotiationRig(t)
	for i := 0; i < maxPendingCandidates+40; i++ {
		rig.s.handleCandidate(rig.peer, &webrtc.ICECandidateInit{Candidate: "candidate:1 1 udp 2130706431 127.0.0.1 50000 typ host"})
	}
	if got := len(rig.peer.pendingCandidates); got != maxPendingCandidates {
		t.Fatalf("expected %d held candidates, have %d", maxPendingCandidates, got)
	}

	rig.s.handleCandidate(rig.peer, &webrtc.ICECandidateInit{Candidate: strings.Repeat("x", maxCandidateBytes+1)})
	if got := len(rig.peer.pendingCandidates); got != maxPendingCandidates {
		t.Fatal("an oversized candidate should be dropped, not held")
	}
}
