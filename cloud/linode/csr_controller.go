package linode

import (
	"context"
	"strings"
	"time"

	"github.com/avast/retry-go"
	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/client-go/informers/certificates/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

type csrController struct {
	kubeclient kubernetes.Interface
	informer   v1.CertificateSigningRequestInformer
}

func newCSRApprover(kubeClient kubernetes.Interface, csrInformer v1.CertificateSigningRequestInformer) *csrController {
	return &csrController{
		kubeclient: kubeClient,
		informer:   csrInformer,
	}
}

func (csrInformer *csrController) Run(stopCh <-chan struct{}) {
	csrNamePrefix := "system:node:"

	csrInformer.informer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			csr := obj.(*certv1.CertificateSigningRequest)

			for _, cond := range csr.Status.Conditions {
				if cond.Type != "" {
					// ignore approving if a csr is either approved, denied or failed
					klog.Infof("returning as csr %s is approved, denied or failed", csr.Name)
					return
				}
			}

			if csr.Spec.SignerName != certv1.KubeletServingSignerName || !strings.HasPrefix(csr.Spec.Username, csrNamePrefix) {
				return
			}

			// add the approval condition to the CSR
			csr.Status.Conditions = append(csr.Status.Conditions, certv1.CertificateSigningRequestCondition{
				Type:           certv1.CertificateApproved,
				Status:         corev1.ConditionTrue,
				LastUpdateTime: metav1.Now(),
				Reason:         "AutoApproved",
				Message:        "Kubelet certificates are automatically approved.",
			})

			// retry 3 times to prevent failure due to connectivity issues.
			retryErr := retry.Do(
				func() error {
					_, err := csrInformer.kubeclient.CertificatesV1().CertificateSigningRequests().UpdateApproval(context.TODO(), csr.Name, csr, metav1.UpdateOptions{})
					return err
				},
				retry.Attempts(3),
				retry.Delay(100*time.Millisecond),
				retry.DelayType(retry.BackOffDelay),
				retry.OnRetry(func(n uint, err error) {
					klog.Errorf("error in approving csr, Retry attempt %d due to error: %s", n, err)
				}),
			)

			if retryErr != nil {
				klog.Errorf("error in approving csr in 3 attempts: %s", retryErr)
				return
			}

			klog.Infof("CSR %s from node %s approved", csr.Name, csr.Spec.Username)
		},
	})

	csrInformer.informer.Informer().Run(stopCh)
}
