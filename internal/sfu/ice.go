package sfu

import (
	"fmt"
	"strings"

	"github.com/pion/webrtc/v4"
)

// summarizeICEServersForLog renders one slog-safe string per ICE server with
// any credential replaced by "***". Use this whenever logging the resolved
// ICE configuration so TURN passwords never end up in stdout, log files, or
// log-aggregation systems.
func summarizeICEServersForLog(servers []webrtc.ICEServer) []string {
	out := make([]string, 0, len(servers))
	for _, srv := range servers {
		urls := strings.Join(srv.URLs, ",")
		hasCred := false
		switch cred := srv.Credential.(type) {
		case string:
			hasCred = strings.TrimSpace(cred) != ""
		case nil:
			hasCred = false
		default:
			hasCred = true
		}
		switch {
		case srv.Username != "" && hasCred:
			out = append(out, fmt.Sprintf("%s (user=%s, credential=***)", urls, srv.Username))
		case srv.Username != "":
			out = append(out, fmt.Sprintf("%s (user=%s, credential=<missing>)", urls, srv.Username))
		case hasCred:
			out = append(out, fmt.Sprintf("%s (credential=***, no-user)", urls))
		default:
			out = append(out, urls)
		}
	}
	return out
}

func parseBootstrapIceServers(entries []bootstrapIceServer) []webrtc.ICEServer {
	servers := make([]webrtc.ICEServer, 0, len(entries))
	for _, entry := range entries {
		var urls []string
		switch v := entry.URLs.(type) {
		case string:
			if s := strings.TrimSpace(v); s != "" {
				urls = append(urls, s)
			}
		case []any:
			for _, item := range v {
				if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
					urls = append(urls, strings.TrimSpace(s))
				}
			}
		}
		if len(urls) == 0 {
			continue
		}
		srv := webrtc.ICEServer{URLs: urls}
		if strings.TrimSpace(entry.Username) != "" {
			srv.Username = entry.Username
		}
		if strings.TrimSpace(entry.Credential) != "" {
			srv.Credential = entry.Credential
		}
		servers = append(servers, srv)
	}
	return servers
}
