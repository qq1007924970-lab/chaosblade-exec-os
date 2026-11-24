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
	"github.com/chaosblade-io/chaosblade-spec-go/channel"
	"golang.org/x/sys/unix"
	"os"
	"strconv"
	"testing"
)

// A target opened through a PID and through /proc/self must contend on the
// same inode even if the executors resolve /tmp in different mount namespaces.
func TestTargetNetnsSharesLocalLock(t *testing.T) {
	ctx := context.WithValue(context.Background(), channel.NSNetFlagName, "true")
	ctx = context.WithValue(ctx, channel.NSTargetFlagName, strconv.Itoa(os.Getpid()))
	f, err := lockNetns(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	other, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err = unix.Flock(int(other.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != unix.EWOULDBLOCK {
		t.Fatalf("second lock: %v", err)
	}
}
