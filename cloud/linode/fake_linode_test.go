package linode

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/linode/linodego"
)

// the only supported API version
const apiVersion = "v4"

type fakeAPI struct {
	t   *testing.T
	nb  map[string]*linodego.NodeBalancer
	nbc map[string]*linodego.NodeBalancerConfig
	nbn map[string]*linodego.NodeBalancerNode

	requests map[fakeRequest]struct{}
}

type fakeRequest struct {
	Path   string
	Body   string
	Method string
}

func newFake(t *testing.T) *fakeAPI {
	return &fakeAPI{
		t:        t,
		nb:       make(map[string]*linodego.NodeBalancer),
		nbc:      make(map[string]*linodego.NodeBalancerConfig),
		nbn:      make(map[string]*linodego.NodeBalancerNode),
		requests: make(map[fakeRequest]struct{}),
	}
}

func (f *fakeAPI) ResetRequests() {
	f.requests = make(map[fakeRequest]struct{})
}

func (f *fakeAPI) recordRequest(r *http.Request) {
	bodyBytes, _ := ioutil.ReadAll(r.Body)
	r.Body.Close()
	r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
	f.requests[fakeRequest{
		Path:   r.URL.Path,
		Method: r.Method,
		Body:   string(bodyBytes),
	}] = struct{}{}
}

func (f *fakeAPI) didRequestOccur(method, path, body string) bool {
	_, ok := f.requests[fakeRequest{
		Path:   path,
		Method: method,
		Body:   body,
	}]
	return ok
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.recordRequest(r)
	fmt.Println("serving request " + r.Method + " " + r.URL.Path)

	w.Header().Set("Content-Type", "application/json")
	urlPath := r.URL.Path

	// if !strings.HasPrefix(urlPath, "/"+apiVersion) {
	// 	http.Error(w, "not found", http.StatusNotFound)
	// 	return
	// }
	// urlPath = strings.TrimPrefix(urlPath, "/"+apiVersion)

	switch r.Method {
	case "GET":
		whichAPI := strings.Split(urlPath[1:], "/")
		fmt.Println(whichAPI)
		switch whichAPI[1] {
		case "nodebalancers":
			rx, _ := regexp.Compile("/v4/nodebalancers/[0-9]+/configs/[0-9]+/nodes/[0-9]+")
			if rx.MatchString(urlPath) {
				id := filepath.Base(urlPath)
				nbn, found := f.nbn[id]
				if found {
					rr, _ := json.Marshal(nbn)
					_, _ = w.Write(rr)

				} else {
					w.WriteHeader(404)
					resp := linodego.APIError{
						Errors: []linodego.APIErrorReason{
							{Reason: "Not Found"},
						},
					}
					rr, _ := json.Marshal(resp)
					_, _ = w.Write(rr)
				}
				return
			}
			rx, _ = regexp.Compile("/v4/nodebalancers/[0-9]+/configs/[0-9]+/nodes")
			if rx.MatchString(urlPath) {
				res := 0
				parts := strings.Split(urlPath[1:], "/")
				nbcID, err := strconv.Atoi(parts[4])
				if err != nil {
					f.t.Fatal(err)
				}

				data := []linodego.NodeBalancerNode{}

				for _, nbn := range f.nbn {
					if nbcID == nbn.ConfigID {
						data = append(data, *nbn)
					}
				}

				resp := linodego.NodeBalancerNodesPagedResponse{
					PageOptions: &linodego.PageOptions{
						Page:    1,
						Pages:   1,
						Results: res,
					},
					Data: data,
				}
				rr, _ := json.Marshal(resp)
				_, _ = w.Write(rr)
				return
			}
			rx, _ = regexp.Compile("/v4/nodebalancers/[0-9]+/configs/[0-9]+")
			if rx.MatchString(urlPath) {
				id := filepath.Base(urlPath)
				nbc, found := f.nbc[id]
				if found {
					rr, _ := json.Marshal(nbc)
					_, _ = w.Write(rr)

				} else {
					w.WriteHeader(404)
					resp := linodego.APIError{
						Errors: []linodego.APIErrorReason{
							{Reason: "Not Found"},
						},
					}
					rr, _ := json.Marshal(resp)
					_, _ = w.Write(rr)
				}
				return
			}
			rx, _ = regexp.Compile("/v4/nodebalancers/[0-9]+/configs")
			if rx.MatchString(urlPath) {
				res := 0
				data := []linodego.NodeBalancerConfig{}
				filter := r.Header.Get("X-Filter")
				if filter == "" {
					for _, n := range f.nbc {
						data = append(data, *n)
					}
				} else {
					var fs map[string]string
					err := json.Unmarshal([]byte(filter), &fs)
					if err != nil {
						f.t.Fatal(err)
					}
					for _, n := range f.nbc {
						if strconv.Itoa(n.NodeBalancerID) == fs["nodebalancer_id"] {
							data = append(data, *n)
						}
					}
				}
				resp := linodego.NodeBalancerConfigsPagedResponse{
					PageOptions: &linodego.PageOptions{
						Page:    1,
						Pages:   1,
						Results: res,
					},
					Data: data,
				}
				rr, _ := json.Marshal(resp)
				_, _ = w.Write(rr)
				return
			}
			rx, _ = regexp.Compile("/v4/nodebalancers/[0-9]+")
			if rx.MatchString(urlPath) {
				id := filepath.Base(urlPath)
				nb, found := f.nb[id]
				if found {
					rr, _ := json.Marshal(nb)
					_, _ = w.Write(rr)

				} else {
					w.WriteHeader(404)
					resp := linodego.APIError{
						Errors: []linodego.APIErrorReason{
							{Reason: "Not Found"},
						},
					}
					rr, _ := json.Marshal(resp)
					_, _ = w.Write(rr)
				}
				return
			}
			rx, _ = regexp.Compile("/v4/nodebalancers")
			if rx.MatchString(urlPath) {
				res := 0
				data := []linodego.NodeBalancer{}
				filter := r.Header.Get("X-Filter")
				if filter == "" {
					for _, n := range f.nb {
						data = append(data, *n)
					}
				} else {
					var fs map[string]string
					err := json.Unmarshal([]byte(filter), &fs)
					if err != nil {
						f.t.Fatal(err)
					}
					for _, n := range f.nb {
						if (n.Label != nil && fs["label"] != "" && *n.Label == fs["label"]) ||
							(fs["ipv4"] != "" && n.IPv4 != nil && *n.IPv4 == fs["ipv4"]) {
							data = append(data, *n)
						}
					}
				}
				resp := linodego.NodeBalancersPagedResponse{
					PageOptions: &linodego.PageOptions{
						Page:    1,
						Pages:   1,
						Results: res,
					},
					Data: data,
				}
				rr, _ := json.Marshal(resp)
				_, _ = w.Write(rr)
				return
			}

		}

	case "POST":
		tp := filepath.Base(r.URL.Path)
		if tp == "nodebalancers" {
			nbco := linodego.NodeBalancerCreateOptions{}
			if err := json.NewDecoder(r.Body).Decode(&nbco); err != nil {
				f.t.Fatal(err)
			}

			ip := net.IPv4(byte(rand.Intn(100)), byte(rand.Intn(100)), byte(rand.Intn(100)), byte(rand.Intn(100))).String()
			hostname := fmt.Sprintf("nb-%s.%s.linode.com", strings.Replace(ip, ".", "-", 4), strings.ToLower(nbco.Region))
			nb := linodego.NodeBalancer{
				ID:       rand.Intn(9999),
				Label:    nbco.Label,
				Region:   nbco.Region,
				IPv4:     &ip,
				Hostname: &hostname,
				Tags:     nbco.Tags,
			}

			if nbco.ClientConnThrottle != nil {
				nb.ClientConnThrottle = *nbco.ClientConnThrottle
			}
			f.nb[strconv.Itoa(nb.ID)] = &nb

			for _, nbcco := range nbco.Configs {
				if nbcco.Protocol == "https" {
					if !strings.Contains(nbcco.SSLCert, "BEGIN CERTIFICATE") {
						f.t.Fatal("HTTPS port declared without calid ssl cert", nbcco.SSLCert)
					}
					if !strings.Contains(nbcco.SSLKey, "BEGIN RSA PRIVATE KEY") {
						f.t.Fatal("HTTPS port declared without calid ssl key", nbcco.SSLKey)
					}
				}
				nbc := linodego.NodeBalancerConfig{
					ID:             rand.Intn(9999),
					Port:           nbcco.Port,
					Protocol:       nbcco.Protocol,
					ProxyProtocol:  nbcco.ProxyProtocol,
					Algorithm:      nbcco.Algorithm,
					Stickiness:     nbcco.Stickiness,
					Check:          nbcco.Check,
					CheckInterval:  nbcco.CheckInterval,
					CheckAttempts:  nbcco.CheckAttempts,
					CheckPath:      nbcco.CheckPath,
					CheckBody:      nbcco.CheckBody,
					CheckPassive:   *nbcco.CheckPassive,
					CheckTimeout:   nbcco.CheckTimeout,
					CipherSuite:    nbcco.CipherSuite,
					NodeBalancerID: nb.ID,
					SSLCommonName:  "sslcommonname",
					SSLFingerprint: "sslfingerprint",
					SSLCert:        "<REDACTED>",
					SSLKey:         "<REDACTED>",
				}
				f.nbc[strconv.Itoa(nbc.ID)] = &nbc

				for _, nbnco := range nbcco.Nodes {
					nbn := linodego.NodeBalancerNode{
						ID:             rand.Intn(99999),
						Address:        nbnco.Address,
						Label:          nbnco.Label,
						Weight:         nbnco.Weight,
						Mode:           nbnco.Mode,
						NodeBalancerID: nb.ID,
						ConfigID:       nbc.ID,
					}
					f.nbn[strconv.Itoa(nbn.ID)] = &nbn
				}
			}

			resp, err := json.Marshal(nb)
			if err != nil {
				f.t.Fatal(err)
			}
			_, _ = w.Write(resp)
			return

		} else if tp == "rebuild" {
			parts := strings.Split(r.URL.Path[1:], "/")
			nbcco := new(linodego.NodeBalancerConfigRebuildOptions)
			if err := json.NewDecoder(r.Body).Decode(nbcco); err != nil {
				f.t.Fatal(err)
			}
			nbid, err := strconv.Atoi(parts[2])
			if err != nil {
				f.t.Fatal(err)
			}
			nbcid, err := strconv.Atoi(parts[4])
			if err != nil {
				f.t.Fatal(err)
			}
			if nbcco.Protocol == "https" {
				if !strings.Contains(nbcco.SSLCert, "BEGIN CERTIFICATE") {
					f.t.Fatal("HTTPS port declared without calid ssl cert", nbcco.SSLCert)
				}
				if !strings.Contains(nbcco.SSLKey, "BEGIN RSA PRIVATE KEY") {
					f.t.Fatal("HTTPS port declared without calid ssl key", nbcco.SSLKey)
				}
			}
			nbcc := linodego.NodeBalancerConfig{
				ID:             nbcid,
				Port:           nbcco.Port,
				Protocol:       nbcco.Protocol,
				ProxyProtocol:  nbcco.ProxyProtocol,
				Algorithm:      nbcco.Algorithm,
				Stickiness:     nbcco.Stickiness,
				Check:          nbcco.Check,
				CheckInterval:  nbcco.CheckInterval,
				CheckAttempts:  nbcco.CheckAttempts,
				CheckPath:      nbcco.CheckPath,
				CheckBody:      nbcco.CheckBody,
				CheckPassive:   *nbcco.CheckPassive,
				CheckTimeout:   nbcco.CheckTimeout,
				CipherSuite:    nbcco.CipherSuite,
				NodeBalancerID: nbid,
				SSLCommonName:  "sslcommonname",
				SSLFingerprint: "sslfingerprint",
				SSLCert:        "<REDACTED>",
				SSLKey:         "<REDACTED>",
			}

			f.nbc[strconv.Itoa(nbcc.ID)] = &nbcc
			for k, n := range f.nbn {
				if n.ConfigID == nbcc.ID {
					delete(f.nbn, k)
				}
			}

			for _, n := range nbcco.Nodes {
				node := linodego.NodeBalancerNode{
					ID:             rand.Intn(99999),
					Address:        n.Address,
					Label:          n.Label,
					Weight:         n.Weight,
					Mode:           n.Mode,
					NodeBalancerID: nbid,
					ConfigID:       nbcc.ID,
				}
				f.nbn[strconv.Itoa(node.ID)] = &node
			}
			resp, err := json.Marshal(nbcc)
			if err != nil {
				f.t.Fatal(err)
			}
			_, _ = w.Write(resp)
			return
		} else if tp == "configs" {
			parts := strings.Split(r.URL.Path[1:], "/")
			nbcco := new(linodego.NodeBalancerConfigCreateOptions)
			if err := json.NewDecoder(r.Body).Decode(nbcco); err != nil {
				f.t.Fatal(err)
			}
			nbid, err := strconv.Atoi(parts[2])
			if err != nil {
				f.t.Fatal(err)
			}

			nbcc := linodego.NodeBalancerConfig{
				ID:             rand.Intn(9999),
				Port:           nbcco.Port,
				Protocol:       nbcco.Protocol,
				ProxyProtocol:  nbcco.ProxyProtocol,
				Algorithm:      nbcco.Algorithm,
				Stickiness:     nbcco.Stickiness,
				Check:          nbcco.Check,
				CheckInterval:  nbcco.CheckInterval,
				CheckAttempts:  nbcco.CheckAttempts,
				CheckPath:      nbcco.CheckPath,
				CheckBody:      nbcco.CheckBody,
				CheckPassive:   *nbcco.CheckPassive,
				CheckTimeout:   nbcco.CheckTimeout,
				CipherSuite:    nbcco.CipherSuite,
				NodeBalancerID: nbid,
				SSLCommonName:  "sslcomonname",
				SSLFingerprint: "sslfingerprint",
				SSLCert:        "<REDACTED>",
				SSLKey:         "<REDACTED>",
			}
			f.nbc[strconv.Itoa(nbcc.ID)] = &nbcc

			resp, err := json.Marshal(nbcc)
			if err != nil {
				f.t.Fatal(err)
			}
			_, _ = w.Write(resp)
			return
		} else if tp == "nodes" {
			parts := strings.Split(r.URL.Path[1:], "/")
			nbnco := new(linodego.NodeBalancerNodeCreateOptions)
			if err := json.NewDecoder(r.Body).Decode(nbnco); err != nil {
				f.t.Fatal(err)
			}
			nbid, err := strconv.Atoi(parts[2])
			if err != nil {
				f.t.Fatal(err)
			}
			nbcid, err := strconv.Atoi(parts[4])
			if err != nil {
				f.t.Fatal(err)
			}
			nbn := linodego.NodeBalancerNode{
				ID:             rand.Intn(99999),
				Address:        nbnco.Address,
				Label:          nbnco.Label,
				Status:         "UP",
				Weight:         nbnco.Weight,
				Mode:           nbnco.Mode,
				ConfigID:       nbcid,
				NodeBalancerID: nbid,
			}
			f.nbn[strconv.Itoa(nbn.ID)] = &nbn
			resp, err := json.Marshal(nbn)
			if err != nil {
				f.t.Fatal(err)
			}
			_, _ = w.Write(resp)
			return
		}
	case "DELETE":
		idRaw := filepath.Base(r.URL.Path)
		fmt.Println("Came here to delete")
		fmt.Println(idRaw)
		id, err := strconv.Atoi(idRaw)
		if err != nil {
			f.t.Fatal(err)
		}
		if strings.Contains(r.URL.Path, "nodes") {
			delete(f.nbn, idRaw)
		} else if strings.Contains(r.URL.Path, "configs") {
			delete(f.nbc, idRaw)

			for k, n := range f.nbn {
				if n.ConfigID == id {
					delete(f.nbn, k)
				}
			}
		} else if strings.Contains(r.URL.Path, "nodebalancers") {
			delete(f.nb, idRaw)

			for k, c := range f.nbc {
				if c.NodeBalancerID == id {
					delete(f.nbc, k)
				}
			}

			for k, n := range f.nbn {
				if n.NodeBalancerID == id {
					delete(f.nbn, k)
				}
			}
		}
	case "PUT":
		fmt.Println("came in here to " + r.URL.Path)
		if strings.Contains(r.URL.Path, "nodes") {
			f.t.Fatal("PUT ...nodes is not supported by the mock API")
		} else if strings.Contains(urlPath, "configs") {
			parts := strings.Split(urlPath[1:], "/")
			fmt.Println("into the config messß")
			fmt.Println(parts)
			nbcco := new(linodego.NodeBalancerConfigUpdateOptions)
			if err := json.NewDecoder(r.Body).Decode(nbcco); err != nil {
				f.t.Fatal(err)
			}
			nbcid, err := strconv.Atoi(parts[4])
			if err != nil {
				f.t.Fatal(err)
			}
			nbid, err := strconv.Atoi(parts[2])
			if err != nil {
				f.t.Fatal(err)
			}

			nbcc := linodego.NodeBalancerConfig{
				ID:             nbcid,
				Port:           nbcco.Port,
				Protocol:       nbcco.Protocol,
				ProxyProtocol:  nbcco.ProxyProtocol,
				Algorithm:      nbcco.Algorithm,
				Stickiness:     nbcco.Stickiness,
				Check:          nbcco.Check,
				CheckInterval:  nbcco.CheckInterval,
				CheckAttempts:  nbcco.CheckAttempts,
				CheckPath:      nbcco.CheckPath,
				CheckBody:      nbcco.CheckBody,
				CheckPassive:   *nbcco.CheckPassive,
				CheckTimeout:   nbcco.CheckTimeout,
				CipherSuite:    nbcco.CipherSuite,
				NodeBalancerID: nbid,
				SSLCommonName:  "sslcommonname",
				SSLFingerprint: "sslfingerprint",
				SSLCert:        "<REDACTED>",
				SSLKey:         "<REDACTED>",
			}
			f.nbc[strconv.Itoa(nbcc.ID)] = &nbcc

			for _, n := range nbcco.Nodes {
				node := linodego.NodeBalancerNode{
					ID:             rand.Intn(99999),
					Address:        n.Address,
					Label:          n.Label,
					Weight:         n.Weight,
					Mode:           n.Mode,
					NodeBalancerID: nbid,
					ConfigID:       nbcc.ID,
				}

				f.nbn[strconv.Itoa(node.ID)] = &node
			}

			resp, err := json.Marshal(nbcc)
			if err != nil {
				f.t.Fatal(err)
			}
			_, _ = w.Write(resp)
			return
		} else if strings.Contains(r.URL.Path, "nodebalancer") {
			parts := strings.Split(r.URL.Path[1:], "/")
			fmt.Println("parts are: ")
			fmt.Println(parts)
			nbuo := new(linodego.NodeBalancerUpdateOptions)
			if err := json.NewDecoder(r.Body).Decode(nbuo); err != nil {
				f.t.Fatal(err)
			}
			if _, err := strconv.Atoi(parts[2]); err != nil {
				f.t.Fatal(err)
			}

			if nb, found := f.nb[parts[2]]; found {
				if nbuo.ClientConnThrottle != nil {
					nb.ClientConnThrottle = *nbuo.ClientConnThrottle
				}
				if nbuo.Label != nil {
					nb.Label = nbuo.Label
				}
				if nbuo.Tags != nil {
					nb.Tags = *nbuo.Tags
				}

				f.nb[strconv.Itoa(nb.ID)] = nb
				resp, err := json.Marshal(nb)
				if err != nil {
					f.t.Fatal(err)
				}
				_, _ = w.Write(resp)
				return
			}

			w.WriteHeader(404)
			resp := linodego.APIError{
				Errors: []linodego.APIErrorReason{
					{Reason: "Not Found"},
				},
			}
			rr, _ := json.Marshal(resp)
			_, _ = w.Write(rr)

		}
	}
}

func randString(n int) string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
