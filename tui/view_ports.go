package tui

import (
	models "github.com/volknichtx/argus/model"
)

func portToRow(port models.Port) row {
	pid := dim(unknownValue)
	if port.PID >= 0 {
		pid = dim(itoa(port.PID))
	}

	return row{
		dim(port.Protocol),
		toned(port.Addr, toneForListenAddr(port)),
		txt(port.Port),
		dim(port.State),
		pid,
		valueOrUnknown(port.Process),
	}
}
