package linode

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"

	certificatesv1 "k8s.io/api/certificates/v1"
	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/ptr"
)

func createCSR(clientset kubernetes.Interface, csrName, username string, csrPEM []byte, approvedStatus certificatesv1.CertificateSigningRequestStatus) error {
	csrObj := &certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: csrName,
		},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Request:           csrPEM,
			SignerName:        "kubernetes.io/kubelet-serving",
			ExpirationSeconds: ptr.To(int32(86400 * 365)), // 1 year
			Usages: []certificatesv1.KeyUsage{
				certificatesv1.UsageClientAuth,
			},
			Username: username,
		},
		Status: approvedStatus,
	}

	_, err := clientset.CertificatesV1().CertificateSigningRequests().Create(context.TODO(), csrObj, metav1.CreateOptions{})
	return err
}

func TestCSRApproval(t *testing.T) {

	testCases := []struct {
		name           string
		csrName        string
		csrUserName    string
		csrPEM         []byte
		outLog         string
		approved       bool
		approvedStatus certificatesv1.CertificateSigningRequestStatus
	}{
		{
			name:        "test approving csr",
			csrName:     "csr-pending",
			csrUserName: "system:node:test",
			csrPEM:      []byte("test-content"),
			approved:    true,
			outLog:      "CSR csr-pending from node system:node:test approved",
		},
		{
			name:        "test approved csr",
			csrName:     "csr-approve",
			csrUserName: "system:node:test",
			csrPEM:      []byte("test-content"),
			approved:    false,
			outLog:      "returning as csr csr-approve is approved, denied or failed",
			approvedStatus: certificatesv1.CertificateSigningRequestStatus{
				Conditions: []certificatesv1.CertificateSigningRequestCondition{
					{
						Type:    certv1.CertificateApproved,
						Status:  corev1.ConditionTrue,
						Reason:  "AutoApproved",
						Message: "Kubelet certificates are automatically approved.",
					},
				},
			},
		},
		{
			name:        "test un-matched csr",
			csrName:     "test",
			csrUserName: "csr-test",
			csrPEM:      []byte("test-content"),
			approved:    false,
			outLog:      "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// create a informer
			var clientset kubernetes.Interface = fake.NewSimpleClientset()
			factory := informers.NewSharedInformerFactory(clientset, 0)
			csrApproveInf := factory.Certificates().V1().CertificateSigningRequests()
			csrApprover := newCSRApprover(clientset, csrApproveInf)

			err := createCSR(clientset, tc.csrName, tc.csrUserName, tc.csrPEM, tc.approvedStatus)
			if err != nil {
				t.Fatalf(err.Error())
			}

			// buffer the stderr to a variable
			r, w, _ := os.Pipe()
			os.Stderr = w
			old := os.Stderr

			// run the informer
			stopCh := make(chan struct{})
			go csrApprover.Run(stopCh)
			if !cache.WaitForCacheSync(stopCh, csrApprover.informer.Informer().HasSynced) {
				t.Fatal("Timed out waiting for caches to sync")
			}
			close(stopCh)
			w.Close()

			// read and reset back the buffer
			out, _ := io.ReadAll(r)
			os.Stderr = old

			if tc.approved {
				fetchedCSR, err := clientset.CertificatesV1().CertificateSigningRequests().Get(context.Background(), tc.csrName, metav1.GetOptions{})
				if err != nil {
					t.Fatalf(err.Error())
				}

				testApproved := false
				for _, cond := range fetchedCSR.Status.Conditions {
					if cond.Type == certv1.CertificateApproved {
						testApproved = true
						break
					}
				}

				if !testApproved {
					t.Errorf("Expected: csr %s to be approved, Got: Not approved.", tc.csrName)
				}
			}

			if !strings.Contains(string(out), tc.outLog) {
				outMessage := strings.Trim(strings.Split(string(out), "] ")[1], "\r\n")
				t.Errorf("Expected: %s, Got: %s", tc.outLog, outMessage)
			}
		})
	}
}
