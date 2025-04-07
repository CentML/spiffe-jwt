package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/alecthomas/kong"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// SpiffeJWT periodically refreshes a JWT SVID from the SPIFFE agent and writes it to a file.
// If it fails to fetch the JWT SVID, it will log an error and exit.
type SpiffeJWT struct {
	DaemonMode              bool          `env:"DAEMON_MODE" help:"Run in daemon mode." default:"true"`
	HealthPort              string        `env:"HEALTH_PORT" help:"Port to listen for health checks." default:"8080"`
	JWTAudience             string        `env:"JWT_AUDIENCE" help:"Audience of the JWT." required:""`
	JWTFileName             string        `env:"JWT_FILE_NAME" help:"Name of the file to write the JWT SVID to." required:""`
	SpiffeAgentSocket       string        `env:"SPIFFE_AGENT_SOCKET" help:"File name of the SPIFFE agent socket" required:""`
	RefreshIntervalOverride time.Duration `env:"REFRESH_INTERVAL_OVERRIDE" help:"Override the default refresh interval (e.g., 30s, 5m)."`

	// Atomic flag to track if initial JWT has been fetched
	started int32 // 0 = false, 1 = true
}

func main() {
	s := &SpiffeJWT{}
	kong.Parse(s)

	if s.DaemonMode {
		logrus.Info("Running in daemon mode")
		go s.run()
		s.startHealthServer()
	} else {
		logrus.Info("Running in one-shot mode")
		jwt, err := s.fetchAndWriteJWTSVID()
		if err != nil {
			logrus.WithError(err).Fatal("unable to fetch or write JWT SVID, shutting down")
		}
		logrus.Infof("JWT SVID fetched and written, it expires in %s", time.Until(jwt.Expiry))
	}
}

// run is the main loop of SpiffeJWT. It fetches a JWT SVID from the SPIFFE agent,
// writes it to a file and refreshes it periodically.
func (s *SpiffeJWT) run() {
	jwt, err := s.fetchAndWriteJWTSVID()
	if err != nil {
		logrus.WithError(err).Fatal("unable to fetch or write JWT SVID, shutting down")
	}

	// Set started flag atomically (for health check)
	atomic.StoreInt32(&s.started, 1)

	// Calculate and set initial refresh interval
	intv := s.getRefreshInterval(jwt)
	logrus.Infof("Ticker started, refreshing JWT SVID in %s", intv)
	ticker := time.NewTicker(intv)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			jwt, err := s.fetchAndWriteJWTSVID()
			if err != nil {
				logrus.WithError(err).Fatal("unable to fetch or write JWT SVID, shutting down")
			}

			// Update refresh interval based on new token expiry
			intv := s.getRefreshInterval(jwt)
			logrus.Infof("JWT SVID will be refreshed in %s", intv)
			ticker.Reset(intv)
		}
	}
}

// fetchAndWriteJWTSVID fetches a JWT SVID from the SPIFFE agent and writes it to a file
func (s *SpiffeJWT) fetchAndWriteJWTSVID() (*jwtsvid.SVID, error) {
	jwt, err := s.fetchJWTSVID()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWT: %w", err)
	}

	if err := s.writeJWTSVID(jwt); err != nil {
		return nil, fmt.Errorf("failed to write JWT: %w", err)
	}

	return jwt, nil
}

// fetchJWTSVID fetches a JWT SVID from the SPIFFE agent
func (s *SpiffeJWT) fetchJWTSVID() (*jwtsvid.SVID, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create connection to SPIFFE agent
	jwtSource, err := workloadapi.NewJWTSource(ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr("unix://"+s.SpiffeAgentSocket)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT source: %w", err)
	}
	logrus.Info("JWT source created")
	defer jwtSource.Close()

	// Fetch validated JWT SVID
	jwt, err := jwtSource.FetchJWTSVID(ctx, jwtsvid.Params{Audience: s.JWTAudience})
	if err != nil {
		return nil, fmt.Errorf("unable to fetch JWT SVID: %w", err)
	}
	logrus.Info("JWT SVID fetched and validated")

	return jwt, nil
}

// writeJWTSVID writes a JWT SVID to a file with secure permissions
func (s *SpiffeJWT) writeJWTSVID(jwt *jwtsvid.SVID) error {
	err := os.WriteFile(s.JWTFileName, []byte(jwt.Marshal()), 0644)
	if err != nil {
		return fmt.Errorf("failed to write JWT file: %w", err)
	}
	logrus.Infof("JWT SVID written to %s", s.JWTFileName)
	return nil
}

// getRefreshInterval calculates safe refresh interval with these priorities:
// 1. Use override if set and valid
// 2. Never exceed 80% of token lifetime
// 3. Default to 50% of remaining lifetime
func (s *SpiffeJWT) getRefreshInterval(svid *jwtsvid.SVID) time.Duration {
	remaining := time.Until(svid.Expiry)
	maxAllowed := time.Duration(float64(remaining) * 0.8) // Use 80% of total lifetime

	// Calculate proposed interval
	var intv time.Duration
	switch {
	case s.RefreshIntervalOverride > 0:
		intv = s.RefreshIntervalOverride
	default:
		intv = remaining / 2
	}

	// Apply safety limits
	if intv > maxAllowed {
		intv = maxAllowed
	}
	if intv < time.Second {
		intv = time.Second // Minimum refresh interval
	}

	return intv
}

// startHealthServer runs HTTP server for health checks
func (s *SpiffeJWT) startHealthServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/started", func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&s.started) == 1 {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	})

	server := &http.Server{
		Addr:         ":" + s.HealthPort,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	logrus.Infof("Starting health server on port %s", s.HealthPort)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logrus.WithError(err).Fatal("Health server failed")
	}
}
