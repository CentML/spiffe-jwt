package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/alecthomas/kong"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// SpiffeJWT periodically refreshes a JWT SVID from the SPIFFE agent and writes it to a file. If it
// fails to fetch the JWT SVID, it deletes its own pod in order to force the pod to be restarted by its
// owner (e.g. a deployment controller).
type SpiffeJWT struct {
	HealthPort              string `env:"HEALTH_PORT" help:"Port to listen for health checks." default:"8080"`
	JWTAudience             string `env:"JWT_AUDIENCE" help:"Audience of the JWT." required:""`
	JWTFileName             string `env:"JWT_FILE_NAME" help:"Name of the file to write the JWT SVID to." required:""`
	PodName                 string `env:"POD_NAME" help:"Name of the pod." required:""`
	PodNamespace            string `env:"POD_NAMESPACE" help:"Namespace of the pod. required:"`
	SpiffeAgentSocket       string `env:"SPIFFE_AGENT_SOCKET" help:"File name of the SPIFFE agent socket" required:""`
	RefreshIntervalOverride int    `env:"REFRESH_INTERVAL_OVERRIDE" help:"Override the default refresh interval in seconds."`
	Started                 bool
}

func main() {

	s := &SpiffeJWT{}
	kong.Parse(s)
	go s.run()
	s.startHealthServer()

}

// run is the main loop of SpiffeJWT. It fetches a JWT SVID from the SPIFFE agent,
// writes it to a file and refreshes it periodically.
func (s *SpiffeJWT) run() {
	// Initial fetch of the JWT SVID
	jwt, err := s.fetchJWTSVID()
	if err != nil {
		logrus.WithError(err).Error("unable to fetch JWT SVID, deleting own pod")
		s.deleteOwnPod()
	}

	// Write the JWT SVID to the configured file
	err = s.writeJWTSVID(jwt)
	if err != nil {
		logrus.Error("since unable to write JWT SVID to file, deleting own pod")
		s.deleteOwnPod()
	}

	// Indicate that spiffe-jwt-svid has received it's first JWT SVID (for start probe)
	s.Started = true

	// Start the ticker
	intv := getRefreshInterval(jwt)
	logrus.Infof("Ticker started, refreshing JWT SVID in %s", intv)
	ticker := time.NewTicker(intv)
	defer ticker.Stop()

	for {
		select {
		// wait for the ticker to fire
		case <-ticker.C:
			jwt, err := s.fetchJWTSVID()
			if err != nil {
				logrus.WithError(err).Error("unable to fetch JWT SVID, deleting own pod")
				s.deleteOwnPod()
				return
			}
			intv := getRefreshInterval(jwt)
			logrus.Infof("JWT SVID will be refreshed in %s", intv)
			ticker.Reset(intv)
		}
	}
}

// fetchJWTSVID fetches a JWT SVID from the SPIFFE agent
func (s *SpiffeJWT) fetchJWTSVID() (*jwtsvid.SVID, error) {
	adr := workloadapi.WithAddr("unix://" + s.SpiffeAgentSocket)
	jwtSource, err := workloadapi.NewJWTSource(context.Background(), workloadapi.WithClientOptions(adr))
	if err != nil {
		return nil, err
	}
	logrus.Info("JWT source created")
	jwt, err := jwtSource.FetchJWTSVID(context.Background(), jwtsvid.Params{Audience: s.JWTAudience})

	if err != nil {
		return nil, fmt.Errorf("unable to getch JWT SVID: %w", err)
	}
	logrus.Info("JWT SVID fetched")

	jwtstr := jwt.Marshal()
	_, err = jwtsvid.ParseAndValidate(jwtstr, jwtSource, []string{s.JWTAudience})
	if err != nil {
		return nil, fmt.Errorf("unable to parse and validate JWT SVID: %w", err)
	}
	logrus.Info("JWT SVID parsed and validated")
	return jwt, nil
}

func (s *SpiffeJWT) writeJWTSVID(jwt *jwtsvid.SVID) error {
	err := os.WriteFile(s.JWTFileName, []byte(jwt.Marshal()), 0644)
	if err != nil {
		return fmt.Errorf("unable to write JWT SVID to file: %w", err)
	}
	logrus.Infof("JWT SVID written to %s", s.JWTFileName)
	return nil
}

// deleteOwnPod deletes the pod in which the agent is running. This is done to force the pod to be restarted by its controller.
func (s *SpiffeJWT) deleteOwnPod() {
	// Create an in-cluster configuration
	config, err := rest.InClusterConfig()
	if err != nil {
		logrus.Fatalf("Error creating in-cluster config: %v\n", err)
	}

	// Create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		logrus.Fatalf("Error creating clientset: %v\n", err)
	}

	logrus.Infof("Attempting to delete pod %s/%s", s.PodNamespace, s.PodName)

	// Delete the pod. If the pod is managed by a controller, it will be re-created.
	deletePolicy := metav1.DeletePropagationForeground
	err = clientset.CoreV1().Pods(s.PodNamespace).Delete(context.Background(), s.PodName, metav1.DeleteOptions{
		PropagationPolicy: &deletePolicy,
	})
	if err != nil {
		logrus.Fatalf("Error deleting pod: %v\n", err)
	}

	fmt.Printf("Pod %s/%s deletion initiated. The pod will be restarted by its controller.\n", s.PodNamespace, s.PodName)

	// sleep for a while to give the controller time to restart the pod without restarting this container
	time.Sleep(60 * time.Second)
}

func (s *SpiffeJWT) getRefreshInterval(svid *jwtsvid.SVID) time.Duration {
	// if the refresh interval override is set, use it
	if s.RefreshIntervalOverride != 0 {
		return time.Duration(s.RefreshIntervalOverride) * time.Second
	}

	// otherwise, return half the time until the SVID expires
	return time.Until(svid.Expiry)/2 + time.Second
}

// startHealthServer starts a health server that listens on /start and returns a 200 if the agent has started and a 503 if it hasn't.
func (s *SpiffeJWT) startHealthServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/started", func(w http.ResponseWriter, r *http.Request) {
		if s.Started {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Started"))
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("Not started"))
		}
	})
	logrus.Infof("Starting health server on port %s", s.HealthPort)
	http.ListenAndServe(":8080", mux)
}
