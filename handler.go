package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
)

func handleTraffic(ctx context.Context, clashHost string, clashToken string) {
	var clashUrl string
	if clashToken == "" {
		clashUrl = fmt.Sprintf("ws://%s/traffic", clashHost)
	} else {
		clashUrl = fmt.Sprintf("ws://%s/traffic?token=%s", clashHost, clashToken)
	}
	ch := dialWebsocketChan(ctx, clashUrl)

	for buf := range ch {
		record := struct {
			Upload   int64 `json:"up"`
			Download int64 `json:"down"`
		}{}

		if err := json.Unmarshal(buf, &record); err != nil {
			println(err.Error())
			continue
		}

		queue <- influxdb2.NewPoint(
			"Traffic",
			map[string]string{},
			map[string]interface{}{
				"upload":   record.Upload,
				"download": record.Download,
			},
			time.Now(),
		)
	}
}

func handleTracing(ctx context.Context, clashHost string, clashToken string) {
	var clashUrl string
	if clashToken == "" {
		clashUrl = fmt.Sprintf("ws://%s/profile/tracing", clashHost)
	} else {
		clashUrl = fmt.Sprintf("ws://%s/profile/tracing?token=%s", clashHost, clashToken)
	}
	ch := dialWebsocketChan(ctx, clashUrl)
	for buf := range ch {
		record := Basic{}

		if err := json.Unmarshal(buf, &record); err != nil {
			println(err.Error())
			continue
		}

		tp := record.Type
		if tp == "" {
			fmt.Printf("buf invalid: %s\n", buf)
			continue
		}

		tags := map[string]string{}
		fields := map[string]interface{}{}

		switch tp {
		case "RuleMatch":
			body := EventRuleMatch{}
			if err := json.Unmarshal(buf, &body); err != nil {
				println(err.Error())
				continue
			}
			tags = map[string]string{
				"proxy":   body.Proxy,
				"src_ip":  body.Metadata.SrcIP,
				"host":    body.Metadata.String(),
				"network": body.Metadata.NetWork,
			}
			fields = map[string]interface{}{
				"id":           body.ID,
				"rule":         body.Rule,
				"payload":      body.Payload,
				"dst_ip":       body.Metadata.DstIP,
				"src_port":     body.Metadata.SrcPort,
				"dst_port":     body.Metadata.DstPort,
				"inbound_type": body.Metadata.Type,
				"duration":     body.Duration,
			}
			if body.Error != "" {
				fields["error"] = body.Error
			}
		case "ProxyDial":
			body := EventProxyDial{}
			if err := json.Unmarshal(buf, &body); err != nil {
				println(err.Error())
				continue
			}
			tags = map[string]string{
				"proxy": body.Proxy,
				"host":  body.Host,
			}
			fields = map[string]interface{}{
				"id":       body.ID,
				"address":  body.Address,
				"chain":    body.Chain,
				"duration": body.Duration,
			}
			if body.Error != "" {
				fields["error"] = body.Error
			}
		case "DNSRequest":
			body := EventDNSRequest{}
			if err := json.Unmarshal(buf, &body); err != nil {
				println(err.Error())
				continue
			}
			tags = map[string]string{
				"name":    body.Name,
				"dnsType": body.DNSType,
			}
			fields = map[string]interface{}{
				"id":       body.ID,
				"duration": body.Duration,
				"answer":   body.Answer,
				"qType":    body.QType,
			}
			if body.Error != "" {
				fields["error"] = body.Error
			}
		default:
			continue
		}

		queue <- influxdb2.NewPoint(
			tp,
			tags,
			fields,
			time.Now(),
		)
	}
}
