package sfu

import (
	"fmt"
	"sync"
	"time"

	"github.com/pion/webrtc/v4"
)

// ─────────────────────────────────────────────
// Room tracks
// ─────────────────────────────────────────────

// roomTrack ties a fanned-out local RTP track to its source peer + SSRC so
// the receiver-side RTCP drain can forward PLI / FIR back to the publisher.
// Receivers asking for a keyframe is how video recovers after packet loss;
// without this association we'd silently swallow those requests.
//
// REMB state lives here too. Each receiver of a fanned-out video track
// emits ReceiverEstimatedMaximumBitrate packets reporting its downlink
// estimate; the SFU aggregates the min across all current receivers and
// forwards that as a single REMB to the publisher. The publisher's
// browser encoder then throttles to the cap. Audio tracks don't use
// REMB (opus doesn't negotiate the goog-remb feedback), so for audio
// the maps stay empty and the aggregation logic is a no-op.
type roomTrack struct {
	Local      *webrtc.TrackLocalStaticRTP
	Publisher  *peer
	RemoteSSRC uint32

	// REMB state. rembMu guards all three fields.
	rembMu          sync.Mutex
	rembPerReceiver map[string]uint64 // receiver_user_id -> latest REMB in bps
	lastSentREMB    uint64            // last bps value we forwarded to publisher; 0 = nothing sent yet
	lastSentREMBAt  time.Time         // throttle baseline
}

// recordReceiverREMB updates the receiver's latest REMB and returns the
// new aggregate (min across all known receivers, in bps). Idempotent
// when the value is unchanged; the caller still gets back the current
// aggregate so it can decide whether to forward.
func (rt *roomTrack) recordReceiverREMB(receiverUserID string, bitrateBPS uint64) uint64 {
	rt.rembMu.Lock()
	defer rt.rembMu.Unlock()
	if rt.rembPerReceiver == nil {
		rt.rembPerReceiver = make(map[string]uint64)
	}
	rt.rembPerReceiver[receiverUserID] = bitrateBPS
	return rt.computeAggregateLocked()
}

// forgetReceiverREMB drops a receiver's REMB record. Called when a peer
// disconnects so the aggregate doesn't stay pinned low because of a
// receiver that left while reporting a bad estimate. Returns the
// post-removal aggregate; 0 means no receivers remain (the publisher's
// cap should be lifted).
func (rt *roomTrack) forgetReceiverREMB(receiverUserID string) uint64 {
	rt.rembMu.Lock()
	defer rt.rembMu.Unlock()
	if rt.rembPerReceiver == nil {
		return 0
	}
	delete(rt.rembPerReceiver, receiverUserID)
	return rt.computeAggregateLocked()
}

// computeAggregateLocked returns the min REMB across all current
// receivers. Caller must hold rembMu.
func (rt *roomTrack) computeAggregateLocked() uint64 {
	var aggregate uint64
	for _, bps := range rt.rembPerReceiver {
		if bps == 0 {
			continue
		}
		if aggregate == 0 || bps < aggregate {
			aggregate = bps
		}
	}
	return aggregate
}

// shouldForwardREMB decides whether a fresh aggregate is worth pushing
// to the publisher. Two triggers:
//
//  1. Significant delta (>20%) from what we last sent. Tightens the
//     loop when the network is changing.
//  2. >2 seconds since the last send. Acts as a heartbeat so a stable
//     low-bandwidth receiver eventually gets honored even after the
//     initial cap is set.
//
// Caller passes the current time so tests don't have to monkey-patch
// the clock. Returns true and atomically records the new send when
// the answer is yes.
func (rt *roomTrack) shouldForwardREMB(aggregate uint64, now time.Time) bool {
	if aggregate == 0 {
		return false
	}
	rt.rembMu.Lock()
	defer rt.rembMu.Unlock()
	last := rt.lastSentREMB
	lastAt := rt.lastSentREMBAt

	const significantDelta = 0.20
	const heartbeatInterval = 2 * time.Second

	var delta float64
	if last == 0 {
		delta = 1.0
	} else if aggregate > last {
		delta = float64(aggregate-last) / float64(last)
	} else {
		delta = float64(last-aggregate) / float64(last)
	}

	if delta >= significantDelta || now.Sub(lastAt) >= heartbeatInterval {
		rt.lastSentREMB = aggregate
		rt.lastSentREMBAt = now
		return true
	}
	return false
}

// ─────────────────────────────────────────────
// Track fanout
// ─────────────────────────────────────────────

func (s *Server) addTrackToPeer(target *peer, rt *roomTrack) error {
	sender, err := target.PC.AddTrack(rt.Local)
	if err != nil {
		return err
	}
	// Drain RTCP from the receiver and forward picture-loss feedback back to
	// the publisher so video can recover after packet loss. Without this the
	// sender would stall (drain is required by pion) AND receivers asking for
	// a keyframe would be silently swallowed. The receiver's user_id is
	// threaded through so REMB reports can be aggregated per publisher.
	go s.forwardReceiverRTCP(sender, rt, target.UserID)

	offer, err := target.PC.CreateOffer(nil)
	if err != nil {
		return err
	}
	if err := target.PC.SetLocalDescription(offer); err != nil {
		return err
	}
	return target.send(signalMessage{
		Type:      "offer",
		SessionID: target.SessionID,
		Offer:     &offer,
	})
}

// handleRemoteTrack proxies RTP from a source peer to all other peers in the room.
// Each fanout runs in a separate goroutine to avoid one slow peer blocking others.
// handleRemoteTrack pumps RTP packets from one publisher's remote track to
// a local forwarder track, with no codec or timing awareness at all — it's
// a byte-level RTP relay. This is why Opus DTX (discontinuous transmission,
// enabled by default per `media_quality.audio.dtx_enabled` on the control
// plane) needs no special handling here: DTX just means the publisher's
// encoder emits RTP packets less often during silence, and ReadRTP/WriteRTP
// below don't care about packet cadence, sequence-number gaps, or payload
// size — those are jitter-buffer/decoder concerns downstream of this
// forwarder, not something the SFU interprets.
func (s *Server) handleRemoteTrack(r *room, srcPeer *peer, remoteTrack *webrtc.TrackRemote) {
	trackKey := fmt.Sprintf("%s:%s", srcPeer.UserID, remoteTrack.ID())

	s.log.Info("remote track started",
		"session_id", r.SessionID,
		"user_id", srcPeer.UserID,
		"track_id", remoteTrack.ID(),
		"codec", remoteTrack.Codec().MimeType,
		"kind", remoteTrack.Kind().String(),
	)

	localTrack, err := webrtc.NewTrackLocalStaticRTP(
		remoteTrack.Codec().RTPCodecCapability,
		fmt.Sprintf("%s-%s", srcPeer.UserID, remoteTrack.ID()),
		"pufferblow",
	)
	if err != nil {
		s.log.Error("failed to create local RTP track",
			"session_id", r.SessionID, "user_id", srcPeer.UserID, "err", err)
		return
	}

	rt := &roomTrack{
		Local:      localTrack,
		Publisher:  srcPeer,
		RemoteSSRC: uint32(remoteTrack.SSRC()),
	}

	// Collect current peers and register the track — all under one lock acquisition.
	r.Mu.Lock()
	r.Tracks[trackKey] = rt
	targets := make([]*peer, 0, len(r.Peers))
	for _, p := range r.Peers {
		if p.UserID != srcPeer.UserID {
			targets = append(targets, p)
		}
	}
	r.Mu.Unlock()

	// Fan out to existing peers in parallel — one goroutine per target.
	// Deafened targets are skipped: they're not forwarding anyone's audio
	// to themselves right now, so there's no point spending upload
	// bandwidth/CPU building a sender they'll just discard. A peer that
	// un-deafens only gets tracks published *after* that point this way —
	// re-attaching everything already live when they un-deafen would need
	// a client-driven "resync" request, which doesn't exist yet.
	var wg sync.WaitGroup
	for _, target := range targets {
		if target.isDeafened() {
			continue
		}
		wg.Add(1)
		go func(t *peer) {
			defer wg.Done()
			if fanErr := s.addTrackToPeer(t, rt); fanErr != nil {
				s.log.Warn("track fanout failed",
					"track_key", trackKey,
					"target_user_id", t.UserID,
					"err", fanErr,
				)
				return
			}
			s.tracksFanned.Add(1)
			s.log.Debug("track fanned",
				"track_key", trackKey,
				"target_user_id", t.UserID,
			)
		}(target)
	}
	wg.Wait()

	// Forward RTP packets from the remote source to the local forwarder.
	for {
		pkt, _, readErr := remoteTrack.ReadRTP()
		if readErr != nil {
			break
		}
		if writeErr := localTrack.WriteRTP(pkt); writeErr != nil {
			break
		}
	}

	r.Mu.Lock()
	delete(r.Tracks, trackKey)
	r.Mu.Unlock()

	s.log.Info("remote track ended",
		"session_id", r.SessionID,
		"user_id", srcPeer.UserID,
		"track_id", remoteTrack.ID(),
	)
}
