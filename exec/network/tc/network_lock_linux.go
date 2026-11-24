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
	"fmt"
	"os"
	"strconv"

	"github.com/chaosblade-io/chaosblade-spec-go/channel"
	"golang.org/x/sys/unix"
)

// The nsfs inode is shared by local and nsexec processes even when they
// have different mount namespaces. Close releases the lock after rollback.
func lockNetns(ctx context.Context) (*os.File, error) {
	pid := "self"
	if ctx.Value(channel.NSNetFlagName) != nil {
		target, _ := ctx.Value(channel.NSTargetFlagName).(string)
		n, err := strconv.Atoi(target)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("invalid network namespace pid %q", target)
		}
		pid = strconv.Itoa(n)
	}
	f, err := os.Open("/proc/" + pid + "/ns/net")
	if err != nil {
		return nil, err
	}
	for {
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX)
		if err != unix.EINTR {
			break
		}
	}
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("lock network namespace: %w", err)
	}
	return f, nil
}
