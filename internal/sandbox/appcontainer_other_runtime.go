//go:build !windows

package sandbox

import (
	"context"
	"fmt"
)

func ProtectRuntime(context.Context, string, string) error {
	return fmt.Errorf("runtime ACL protection unsupported")
}
