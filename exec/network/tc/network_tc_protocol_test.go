/*
 * Copyright 2025 The ChaosBlade Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package tc

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/chaosblade-io/chaosblade-spec-go/spec"
)

func TestProtocolNumbers(t *testing.T) {
	for input, want := range map[string][]string{
		"": {""}, "tcp": {"6"}, "udp": {"17"}, "icmp": {"1"},
		"tcp,udp": {"6", "17"}, "tcp,icmp": {"6", "1"}, "udp,icmp": {"17", "1"},
		"icmp,tcp,udp,tcp": {"1", "6", "17"}, "tcp, udp": {"6", "17"},
	} {
		got, err := protocolNumbers(input)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%q: got %v, %v; want %v", input, got, err, want)
		}
	}
	for _, input := range []string{",", "tcp,", "sctp", "tcp,,udp"} {
		if _, err := protocolNumbers(input); err == nil {
			t.Errorf("accepted %q", input)
		}
	}
}

type protocolTestChannel struct {
	spec.Channel
	filters  string
	commands []string
}

func (ch *protocolTestChannel) Run(ctx context.Context, cmd, args string) *spec.Response {
	ch.commands = append(ch.commands, args)
	switch {
	case strings.HasPrefix(args, "qdisc show"):
		return spec.ReturnSuccess("qdisc netem 40: parent 1:4 limit 1000 delay 100ms")
	case strings.HasPrefix(args, "filter show"):
		return spec.ReturnSuccess(ch.filters)
	default:
		return spec.ReturnSuccess("")
	}
}

func TestMultiProtocolInstallation(t *testing.T) {
	tcp := "filter parent 1: protocol ip pref 4 u32 flowid 1:4\n match 00060000/00ff0000 at 8\n"
	udp := "filter parent 1: protocol ip pref 4 u32 flowid 1:4\n match 00110000/00ff0000 at 8\n"
	for name, filters := range map[string]string{"complete": tcp + udp, "missing": tcp, "wrong band": tcp + strings.Replace(udp, "flowid 1:4", "flowid 1:3", 1)} {
		t.Run(name, func(t *testing.T) {
			ch := &protocolTestChannel{filters: filters}
			res := executeTargetPortAndIpWithExclude(context.Background(), ch, "eth0", "netem delay 100ms", nil, [][]int{{80, 80}}, []string{"match ip dst 192.0.2.2"}, nil, nil, []string{"6", "17"})
			if res.Success != (name == "complete") {
				t.Fatalf("unexpected status: %v", res)
			}
			cmd := ch.commands[0]
			for _, p := range []string{"6", "17"} {
				if !strings.Contains(cmd, "match ip protocol "+p+" 0xff flowid 1:4") {
					t.Errorf("missing %s filter: %s", p, cmd)
				}
			}
			if strings.Count(cmd, "qdisc add") != 1 || strings.Count(cmd, "match ip dport 80") != 2 || strings.Count(cmd, "match ip dst 192.0.2.2") != 2 {
				t.Errorf("unexpected rule set: %s", cmd)
			}
		})
	}
}

func TestRejectICMPAndPortsBeforeInjection(t *testing.T) {
	resp := startNet(context.Background(), "eth0", "netem loss 10%", "", "53", "", "", "", false, false, "udp,icmp", nil)
	if resp.Success {
		t.Fatal("accepted ICMP with a port match")
	}
}
