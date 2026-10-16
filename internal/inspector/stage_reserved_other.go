//go:build !windows

package inspector

func stageReservedComponent(string) bool { return false }
