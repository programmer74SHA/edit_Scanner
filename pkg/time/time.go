package time

import (
	"time"

	"gitlab.apk-group.net/siem/backend/asset-discovery/pkg/logger"
)

var TehranLoc *time.Location

func init() {
	l, err := time.LoadLocation("Asia/Tehran")
	if err != nil {
		logger.Fatal("Failed to load Tehran timezone: %v", err)
	}
	TehranLoc = l
}

func AddMinutes(minute uint, isTehran bool) time.Time {
	now := time.Now()
	if isTehran {
		now = now.In(TehranLoc)
	}
	return now.Add(time.Minute * time.Duration(minute))
}
