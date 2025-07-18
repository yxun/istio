// Code generated by pkg/config/schema/codegen/tools/collections.main.go. DO NOT EDIT.

package gvr

import "k8s.io/apimachinery/pkg/runtime/schema"

var (
	ServiceExport                  = schema.GroupVersionResource{Group: "multicluster.x-k8s.io", Version: "v1alpha1", Resource: "serviceexports"}
	ServiceImport                  = schema.GroupVersionResource{Group: "multicluster.x-k8s.io", Version: "v1alpha1", Resource: "serviceimports"}
	AuthorizationPolicy            = schema.GroupVersionResource{Group: "security.istio.io", Version: "v1", Resource: "authorizationpolicies"}
	AuthorizationPolicy_v1beta1    = schema.GroupVersionResource{Group: "security.istio.io", Version: "v1beta1", Resource: "authorizationpolicies"}
	BackendTLSPolicy               = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1alpha3", Resource: "backendtlspolicies"}
	CertificateSigningRequest      = schema.GroupVersionResource{Group: "certificates.k8s.io", Version: "v1", Resource: "certificatesigningrequests"}
	ClusterTrustBundle             = schema.GroupVersionResource{Group: "certificates.k8s.io", Version: "v1beta1", Resource: "clustertrustbundles"}
	ConfigMap                      = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"}
	CustomResourceDefinition       = schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}
	DaemonSet                      = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"}
	Deployment                     = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	DestinationRule                = schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1", Resource: "destinationrules"}
	DestinationRule_v1alpha3       = schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1alpha3", Resource: "destinationrules"}
	DestinationRule_v1beta1        = schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1beta1", Resource: "destinationrules"}
	EndpointSlice                  = schema.GroupVersionResource{Group: "discovery.k8s.io", Version: "v1", Resource: "endpointslices"}
	Endpoints                      = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "endpoints"}
	EnvoyFilter                    = schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1alpha3", Resource: "envoyfilters"}
	GRPCRoute                      = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "grpcroutes"}
	GRPCRoute_v1alpha2             = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1alpha2", Resource: "grpcroutes"}
	Gateway                        = schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1", Resource: "gateways"}
	Gateway_v1alpha3               = schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1alpha3", Resource: "gateways"}
	Gateway_v1beta1                = schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1beta1", Resource: "gateways"}
	GatewayClass                   = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1beta1", Resource: "gatewayclasses"}
	GatewayClass_v1alpha2          = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1alpha2", Resource: "gatewayclasses"}
	GatewayClass_v1                = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gatewayclasses"}
	HTTPRoute                      = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1beta1", Resource: "httproutes"}
	HTTPRoute_v1alpha2             = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1alpha2", Resource: "httproutes"}
	HTTPRoute_v1                   = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "httproutes"}
	HorizontalPodAutoscaler        = schema.GroupVersionResource{Group: "autoscaling", Version: "v2", Resource: "horizontalpodautoscalers"}
	InferencePool                  = schema.GroupVersionResource{Group: "inference.networking.x-k8s.io", Version: "v1alpha2", Resource: "inferencepools"}
	Ingress                        = schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "ingresses"}
	IngressClass                   = schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "ingressclasses"}
	KubernetesGateway              = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1beta1", Resource: "gateways"}
	KubernetesGateway_v1alpha2     = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1alpha2", Resource: "gateways"}
	KubernetesGateway_v1           = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"}
	Lease                          = schema.GroupVersionResource{Group: "coordination.k8s.io", Version: "v1", Resource: "leases"}
	MeshConfig                     = schema.GroupVersionResource{Group: "", Version: "v1alpha1", Resource: "meshconfigs"}
	MeshNetworks                   = schema.GroupVersionResource{Group: "", Version: "v1alpha1", Resource: "meshnetworks"}
	MutatingWebhookConfiguration   = schema.GroupVersionResource{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "mutatingwebhookconfigurations"}
	Namespace                      = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"}
	Node                           = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "nodes"}
	PeerAuthentication             = schema.GroupVersionResource{Group: "security.istio.io", Version: "v1", Resource: "peerauthentications"}
	PeerAuthentication_v1beta1     = schema.GroupVersionResource{Group: "security.istio.io", Version: "v1beta1", Resource: "peerauthentications"}
	Pod                            = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	PodDisruptionBudget            = schema.GroupVersionResource{Group: "policy", Version: "v1", Resource: "poddisruptionbudgets"}
	ProxyConfig                    = schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1beta1", Resource: "proxyconfigs"}
	ReferenceGrant                 = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1beta1", Resource: "referencegrants"}
	ReferenceGrant_v1alpha2        = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1alpha2", Resource: "referencegrants"}
	RequestAuthentication          = schema.GroupVersionResource{Group: "security.istio.io", Version: "v1", Resource: "requestauthentications"}
	RequestAuthentication_v1beta1  = schema.GroupVersionResource{Group: "security.istio.io", Version: "v1beta1", Resource: "requestauthentications"}
	Secret                         = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}
	Service                        = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "services"}
	ServiceAccount                 = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "serviceaccounts"}
	ServiceEntry                   = schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1", Resource: "serviceentries"}
	ServiceEntry_v1alpha3          = schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1alpha3", Resource: "serviceentries"}
	ServiceEntry_v1beta1           = schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1beta1", Resource: "serviceentries"}
	Sidecar                        = schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1", Resource: "sidecars"}
	Sidecar_v1alpha3               = schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1alpha3", Resource: "sidecars"}
	Sidecar_v1beta1                = schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1beta1", Resource: "sidecars"}
	StatefulSet                    = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "statefulsets"}
	TCPRoute                       = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1alpha2", Resource: "tcproutes"}
	TLSRoute                       = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1alpha2", Resource: "tlsroutes"}
	Telemetry                      = schema.GroupVersionResource{Group: "telemetry.istio.io", Version: "v1", Resource: "telemetries"}
	Telemetry_v1alpha1             = schema.GroupVersionResource{Group: "telemetry.istio.io", Version: "v1alpha1", Resource: "telemetries"}
	UDPRoute                       = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1alpha2", Resource: "udproutes"}
	ValidatingWebhookConfiguration = schema.GroupVersionResource{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingwebhookconfigurations"}
	VirtualService                 = schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1", Resource: "virtualservices"}
	VirtualService_v1alpha3        = schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1alpha3", Resource: "virtualservices"}
	VirtualService_v1beta1         = schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1beta1", Resource: "virtualservices"}
	WasmPlugin                     = schema.GroupVersionResource{Group: "extensions.istio.io", Version: "v1alpha1", Resource: "wasmplugins"}
	WorkloadEntry                  = schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1", Resource: "workloadentries"}
	WorkloadEntry_v1alpha3         = schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1alpha3", Resource: "workloadentries"}
	WorkloadEntry_v1beta1          = schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1beta1", Resource: "workloadentries"}
	WorkloadGroup                  = schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1", Resource: "workloadgroups"}
	WorkloadGroup_v1alpha3         = schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1alpha3", Resource: "workloadgroups"}
	WorkloadGroup_v1beta1          = schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1beta1", Resource: "workloadgroups"}
	XBackendTrafficPolicy          = schema.GroupVersionResource{Group: "gateway.networking.x-k8s.io", Version: "v1alpha1", Resource: "xbackendtrafficpolicies"}
	XListenerSet                   = schema.GroupVersionResource{Group: "gateway.networking.x-k8s.io", Version: "v1alpha1", Resource: "xlistenersets"}
)

func IsClusterScoped(g schema.GroupVersionResource) bool {
	switch g {
	case ServiceExport:
		return false
	case ServiceImport:
		return false
	case AuthorizationPolicy:
		return false
	case AuthorizationPolicy_v1beta1:
		return false
	case BackendTLSPolicy:
		return false
	case CertificateSigningRequest:
		return true
	case ClusterTrustBundle:
		return true
	case ConfigMap:
		return false
	case CustomResourceDefinition:
		return true
	case DaemonSet:
		return false
	case Deployment:
		return false
	case DestinationRule:
		return false
	case DestinationRule_v1alpha3:
		return false
	case DestinationRule_v1beta1:
		return false
	case EndpointSlice:
		return false
	case Endpoints:
		return false
	case EnvoyFilter:
		return false
	case GRPCRoute:
		return false
	case GRPCRoute_v1alpha2:
		return false
	case Gateway:
		return false
	case Gateway_v1alpha3:
		return false
	case Gateway_v1beta1:
		return false
	case GatewayClass:
		return true
	case GatewayClass_v1alpha2:
		return true
	case GatewayClass_v1:
		return true
	case HTTPRoute:
		return false
	case HTTPRoute_v1alpha2:
		return false
	case HTTPRoute_v1:
		return false
	case HorizontalPodAutoscaler:
		return false
	case InferencePool:
		return false
	case Ingress:
		return false
	case IngressClass:
		return true
	case KubernetesGateway:
		return false
	case KubernetesGateway_v1alpha2:
		return false
	case KubernetesGateway_v1:
		return false
	case Lease:
		return false
	case MutatingWebhookConfiguration:
		return true
	case Namespace:
		return true
	case Node:
		return true
	case PeerAuthentication:
		return false
	case PeerAuthentication_v1beta1:
		return false
	case Pod:
		return false
	case PodDisruptionBudget:
		return false
	case ProxyConfig:
		return false
	case ReferenceGrant:
		return false
	case ReferenceGrant_v1alpha2:
		return false
	case RequestAuthentication:
		return false
	case RequestAuthentication_v1beta1:
		return false
	case Secret:
		return false
	case Service:
		return false
	case ServiceAccount:
		return false
	case ServiceEntry:
		return false
	case ServiceEntry_v1alpha3:
		return false
	case ServiceEntry_v1beta1:
		return false
	case Sidecar:
		return false
	case Sidecar_v1alpha3:
		return false
	case Sidecar_v1beta1:
		return false
	case StatefulSet:
		return false
	case TCPRoute:
		return false
	case TLSRoute:
		return false
	case Telemetry:
		return false
	case Telemetry_v1alpha1:
		return false
	case UDPRoute:
		return false
	case ValidatingWebhookConfiguration:
		return true
	case VirtualService:
		return false
	case VirtualService_v1alpha3:
		return false
	case VirtualService_v1beta1:
		return false
	case WasmPlugin:
		return false
	case WorkloadEntry:
		return false
	case WorkloadEntry_v1alpha3:
		return false
	case WorkloadEntry_v1beta1:
		return false
	case WorkloadGroup:
		return false
	case WorkloadGroup_v1alpha3:
		return false
	case WorkloadGroup_v1beta1:
		return false
	case XBackendTrafficPolicy:
		return false
	case XListenerSet:
		return false
	}
	// shouldn't happen
	return false
}
