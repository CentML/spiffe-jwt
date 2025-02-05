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

//const SPIFFE_AGENT_ADRESS = "/var/run/spire/agent-sockets/socket"
//const JWT_AUDIENCE = "sts.amazonaws.com"

type CLI struct {
	HealthPort         string `env:"HEALTH_PORT" help:"Port to listen for health checks." default:"8080"`
	JWTAudience        string `env:"JWT_AUDIENCE" help:"Audience of the JWT." required:""`
	JWTFileName        string `env:"JWT_FILE_NAME" help:"Name of the file to write the JWT SVID to." required:""`
	PodName            string `env:"POD_NAME" help:"Name of the pod." required:""`
	PodNamespace       string `env:"POD_NAMESPACE" help:"Namespace of the pod. required:"`
	SpiffeAgentAddress string `env:"SPIFFE_AGENT_ADDRESS" help:"Address of the SPIFFE agent." required:""`
	Started            bool
}

func main() {

	c := &CLI{}
	kong.Parse(c)
	go c.run()
	c.startHealthServer()

}

// run starts the JWT source and fetches a JWT SVID, if there's an error it deletes the pod it is
// running in to force a restart.
func (c *CLI) run() {
	// Initial fetch of the JWT SVID
	jwt, err := c.fetchJWTSVID()
	if err != nil {
		logrus.WithError(err).Error("unable to fetch JWT SVID, deleting own pod")
		c.deleteOwnPod()
	}

	// Write the JWT SVID to the configured file
	err = c.writeJWTSVID(jwt)
	if err != nil {
		logrus.Error("since unable to write JWT SVID to file, deleting own pod")
		c.deleteOwnPod()
	}

	// Indicate that spiffe-jwt-svid has received it's first JWT SVID (for start probe)
	c.Started = true

	// Start the ticker
	intv := getRefreshInterval(jwt)
	logrus.Infof("Ticker started, refreshing JWT SVID in %s", intv)
	ticker := time.NewTicker(intv)
	defer ticker.Stop()

	for {
		select {
		// wait for the ticker to fire
		case <-ticker.C:
			jwt, err := c.fetchJWTSVID()
			if err != nil {
				logrus.WithError(err).Error("unable to fetch JWT SVID, deleting own pod")
				c.deleteOwnPod()
				return
			}
			intv := getRefreshInterval(jwt)
			logrus.Infof("JWT SVID will be refreshed in %s", intv)
			ticker.Reset(intv)
		}
	}
}

// fetchJWTSVID fetches a JWT SVID from the SPIFFE agent
func (c *CLI) fetchJWTSVID() (*jwtsvid.SVID, error) {
	adr := workloadapi.WithAddr("unix://" + c.SpiffeAgentAddress)
	jwtSource, err := workloadapi.NewJWTSource(context.Background(), workloadapi.WithClientOptions(adr))
	if err != nil {
		return nil, err
	}
	logrus.Info("JWT source created")
	jwt, err := jwtSource.FetchJWTSVID(context.Background(), jwtsvid.Params{Audience: c.JWTAudience})

	if err != nil {
		return nil, fmt.Errorf("unable to getch JWT SVID: %w", err)
	}
	logrus.Info("JWT SVID fetched")

	jwtstr := jwt.Marshal()
	_, err = jwtsvid.ParseAndValidate(jwtstr, jwtSource, []string{c.JWTAudience})
	if err != nil {
		return nil, fmt.Errorf("unable to parse and validate JWT SVID: %w", err)
	}
	logrus.Info("JWT SVID parsed and validated")
	return jwt, nil
}

func (c *CLI) writeJWTSVID(jwt *jwtsvid.SVID) error {
	err := os.WriteFile(c.JWTFileName, []byte(jwt.Marshal()), 0644)
	if err != nil {
		return fmt.Errorf("unable to write JWT SVID to file: %w", err)
	}
	logrus.Infof("JWT SVID written to %s", c.JWTFileName)
	return nil
}

// deleteOwnPod deletes the pod in which the agent is running. This is done to force the pod to be restarted by its controller.
func (c *CLI) deleteOwnPod() {
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

	logrus.Infof("Attempting to delete pod %s/%s", c.PodNamespace, c.PodName)

	// Delete the pod. If the pod is managed by a controller, it will be re-created.
	deletePolicy := metav1.DeletePropagationForeground
	err = clientset.CoreV1().Pods(c.PodNamespace).Delete(context.Background(), c.PodName, metav1.DeleteOptions{
		PropagationPolicy: &deletePolicy,
	})
	if err != nil {
		logrus.Fatalf("Error deleting pod: %v\n", err)
	}

	fmt.Printf("Pod %s/%s deletion initiated. The pod will be restarted by its controller.\n", c.PodNamespace, c.PodName)

	// sleep for a while to give the controller time to restart the pod without restarting this container
	time.Sleep(60 * time.Second)
}

func getRefreshInterval(svid *jwtsvid.SVID) time.Duration {
	return time.Until(svid.Expiry)/2 + time.Second
}

// startHealthServer starts a health server that listens on /start and returns a 200 if the agent has started and a 503 if it hasn't.
func (c *CLI) startHealthServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/started", func(w http.ResponseWriter, r *http.Request) {
		if c.Started {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Started"))
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("Not started"))
		}
	})
	logrus.Infof("Starting health server on port %s", c.HealthPort)
	http.ListenAndServe(":8080", mux)
}
