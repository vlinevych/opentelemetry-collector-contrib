// Copyright 2020 OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package k8sattributesprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/k8sattributesprocessor"

import (
	"context"
	"fmt"
	"net"

	"go.opentelemetry.io/collector/client"
	"go.opentelemetry.io/collector/model/pdata"
	conventions "go.opentelemetry.io/collector/model/semconv/v1.5.0"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/k8sattributesprocessor/kube"
)

// extractPodIds extracts IP and pod UID from attributes or request context.
// It returns a value pair containing configured label and IP Address and/or Pod UID.
// If empty value in return it means that attributes does not contains configured label to match resources for Pod.
func extractPodID(ctx context.Context, attrs pdata.AttributeMap, associations []kube.Association) (string, kube.PodIdentifier) {

	log, _ := zap.NewProduction()
	log.Info("VOVA [extractPodID] extractPodID triggered")
	log.Info(fmt.Sprintf("VOVA [extractPodID] Associations: %s", associations))
	log.Info(fmt.Sprintf("VOVA [extractPodID] AttributeMap: %s", attrs))

	// If pod association is not set
	if len(associations) == 0 {
		return extractPodIDNoAssociations(ctx, attrs)
	}

	connectionIP := getConnectionIP(ctx)
	hostname := stringAttributeFromMap(attrs, conventions.AttributeHostName)
	for _, asso := range associations {
		// If association configured to take IP address from connection
		switch {
		case asso.From == "connection" && connectionIP != "":
			log.Info(fmt.Sprintf("VOVA [extractPodID] extracted IP from connection: %s", connectionIP))
			return k8sIPLabelName, connectionIP
		case asso.From == "resource_attribute":
			// If association configured by resource_attribute
			// In k8s environment, host.name label set to a pod IP address.
			// If the value doesn't represent an IP address, we skip it.
			if asso.Name == conventions.AttributeHostName {
				if net.ParseIP(hostname) != nil {
					return k8sIPLabelName, kube.PodIdentifier(hostname)
				}
			} else {
				// Extract values based on configured resource_attribute.
				attributeValue := stringAttributeFromMap(attrs, asso.Name)
				log.Info(fmt.Sprintf("VOVA [extractPodID] trying to extract IP from an attr: %s", asso.Name))
				if attributeValue != "" {
					return asso.Name, kube.PodIdentifier(attributeValue)
				}
			}
		}
	}

	log.Info(fmt.Sprintf("VOVA [extractPodID] extractPodID returns empty"))
	return "", ""
}

func extractPodIDNoAssociations(ctx context.Context, attrs pdata.AttributeMap) (string, kube.PodIdentifier) {
	var podIP, labelIP kube.PodIdentifier
	podIP = kube.PodIdentifier(stringAttributeFromMap(attrs, k8sIPLabelName))

	log, _ := zap.NewProduction()
	log.Info(fmt.Sprintf("VOVA [extractPodIDNoAssociations] triggered"))

	if podIP != "" {
		log.Info(fmt.Sprintf("VOVA [extractPodIDNoAssociations] association: podIP = %s", podIP))
		return k8sIPLabelName, podIP
	}

	labelIP = kube.PodIdentifier(stringAttributeFromMap(attrs, clientIPLabelName))
	if labelIP != "" {
		log.Info(fmt.Sprintf("VOVA [extractPodIDNoAssociations]: labelIP = %s", labelIP))
		return k8sIPLabelName, labelIP
	}

	connectionIP := getConnectionIP(ctx)
	if connectionIP != "" {
		log.Info(fmt.Sprintf("VOVA [extractPodIDNoAssociations]: connectionIP = %s", connectionIP))
		return k8sIPLabelName, connectionIP
	}

	hostname := stringAttributeFromMap(attrs, conventions.AttributeHostName)
	if net.ParseIP(hostname) != nil {
		log.Info(fmt.Sprintf("VOVA [extractPodIDNoAssociations]: PodIdentifier(hostname) = %s", kube.PodIdentifier(hostname)))
		return k8sIPLabelName, kube.PodIdentifier(hostname)
	}

	log.Info(fmt.Sprintf("VOVA [extractPodIDNoAssociations] returns empty list"))
	return "", ""
}

func getConnectionIP(ctx context.Context) kube.PodIdentifier {
	c := client.FromContext(ctx)

	log, _ := zap.NewProduction()
	log.Info(fmt.Sprintf("VOVA [getConnectionIP] returns %s", c.Addr.String()))

	if c.Addr == nil {
		return ""
	}
	return kube.PodIdentifier(c.Addr.String())

}

func stringAttributeFromMap(attrs pdata.AttributeMap, key string) string {
	if val, ok := attrs.Get(key); ok {
		if val.Type() == pdata.AttributeValueTypeString {
			return val.StringVal()
		}
	}
	return ""
}
