package sfu

import (
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/webrtc/v4"
)

// rewriteKeyframeRequests filters a batch of receiver-side RTCP packets and
// returns the PLI / FIR packets rewritten with the publisher's SSRC. The
// helper is extracted from forwardReceiverRTCP so it can be tested without a
// real RTPSender or RTPCConn.
func rewriteKeyframeRequests(packets []rtcp.Packet, publisherSSRC uint32) []rtcp.Packet {
	if publisherSSRC == 0 || len(packets) == 0 {
		return nil
	}
	var out []rtcp.Packet
	for _, pkt := range packets {
		switch p := pkt.(type) {
		case *rtcp.PictureLossIndication:
			out = append(out, &rtcp.PictureLossIndication{
				MediaSSRC: publisherSSRC,
			})
			_ = p // silence linter — we deliberately don't copy other fields
		case *rtcp.FullIntraRequest:
			// Preserve FIR's SequenceNumber/Entries shape but rewrite the
			// target SSRC. A copy avoids racing with the receiver's
			// goroutine if it still holds the original.
			rewritten := *p
			rewritten.MediaSSRC = publisherSSRC
			out = append(out, &rewritten)
		}
	}
	return out
}

// extractMaxBitrateBPS pulls the highest REMB value out of an RTCP batch.
// Each REMB packet carries a single bandwidth estimate; in practice a
// receiver emits one REMB per batch but we tolerate multiple by taking
// the max (the receiver's "I think I can handle up to this" cap).
// Returns 0 when no REMB packet is present.
func extractMaxBitrateBPS(packets []rtcp.Packet) uint64 {
	var max uint64
	for _, pkt := range packets {
		remb, ok := pkt.(*rtcp.ReceiverEstimatedMaximumBitrate)
		if !ok {
			continue
		}
		bps := uint64(remb.Bitrate)
		if bps > max {
			max = bps
		}
	}
	return max
}

// forwardReceiverRTCP pumps RTCP from a receiver's RTPSender. Picture-loss
// indications (PLI) and full-intra requests (FIR) are rewritten with the
// publisher's SSRC and re-emitted on the publisher's peer connection so the
// upstream encoder is asked to generate a fresh keyframe. All other RTCP
// types are drained without forwarding — the SFU itself doesn't process
// them in v1.0, but reading them is mandatory or the sender stalls.
//
// Returns when ReadRTCP errors (typically because the receiver has gone
// away or the connection is closed). Publisher write failures are logged
// at debug because the publisher may have disconnected too, in which case
// the receiver fanout is about to tear down anyway.
func (s *Server) forwardReceiverRTCP(sender *webrtc.RTPSender, rt *roomTrack, receiverUserID string) {
	if sender == nil || rt == nil {
		return
	}
	for {
		packets, _, readErr := sender.ReadRTCP()
		if readErr != nil {
			// Receiver gone — forget their REMB so the aggregate
			// updates to reflect only currently-connected receivers.
			// The new aggregate is intentionally NOT forwarded here:
			// the publisher will pick up the change on the next
			// REMB report from any remaining receiver, and emitting
			// an unsolicited "lift the cap" right at peer-leave time
			// can race with the addTrackToPeer goroutine if a new
			// receiver is joining concurrently.
			rt.forgetReceiverREMB(receiverUserID)
			return
		}
		if rt.Publisher == nil || rt.Publisher.PC == nil || rt.RemoteSSRC == 0 {
			continue
		}

		// Aggregate REMB across all receivers and forward to publisher
		// when the aggregate has moved enough to matter. Done before
		// the PLI/FIR rewrite because the two paths are independent —
		// a single RTCP batch can carry both a REMB and a PLI.
		if rembBPS := extractMaxBitrateBPS(packets); rembBPS > 0 {
			aggregate := rt.recordReceiverREMB(receiverUserID, rembBPS)
			if aggregate > 0 && rt.shouldForwardREMB(aggregate, time.Now()) {
				outgoing := &rtcp.ReceiverEstimatedMaximumBitrate{
					SenderSSRC: 0,
					Bitrate:    float32(aggregate),
					SSRCs:      []uint32{rt.RemoteSSRC},
				}
				if err := rt.Publisher.PC.WriteRTCP([]rtcp.Packet{outgoing}); err != nil {
					s.log.Debug("publisher REMB write failed",
						"publisher_user_id", rt.Publisher.UserID,
						"remote_ssrc", rt.RemoteSSRC,
						"bps", aggregate,
						"err", err,
					)
				} else {
					// Don't log receiver_count here — the field lives
					// under rembMu and a debug-line shouldn't grab the
					// lock again on every forward.
					s.log.Debug("forwarded aggregated REMB to publisher",
						"publisher_user_id", rt.Publisher.UserID,
						"remote_ssrc", rt.RemoteSSRC,
						"bps", aggregate,
					)
				}
			}
		}

		toForward := rewriteKeyframeRequests(packets, rt.RemoteSSRC)
		if len(toForward) == 0 {
			continue
		}
		if err := rt.Publisher.PC.WriteRTCP(toForward); err != nil {
			s.log.Debug("publisher RTCP write failed",
				"publisher_user_id", rt.Publisher.UserID,
				"remote_ssrc", rt.RemoteSSRC,
				"err", err,
			)
			return
		}
		s.log.Debug("forwarded receiver keyframe request to publisher",
			"publisher_user_id", rt.Publisher.UserID,
			"remote_ssrc", rt.RemoteSSRC,
			"count", len(toForward),
		)
	}
}
