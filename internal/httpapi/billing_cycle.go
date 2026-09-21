package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"time"
)

func cyclePolicyDigest(policy map[string]any) string {
	values := map[string]any{}
	for _, key := range []string{"reset", "resetDay", "resetTimezone", "cycleDays"} {
		values[key] = policy[key]
	}
	raw, _ := json.Marshal(values)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func validateCyclePolicy(row map[string]any) error {
	if value, ok := row["cycleDays"]; ok && value != nil {
		days := number(row, "cycleDays")
		if days < 1 || days > 3660 || math.Trunc(days) != days {
			return errors.New("周期天数须为 1 至 3660 的整数")
		}
	}
	if value, ok := row["resetDay"]; ok && value != nil {
		day := number(row, "resetDay")
		if day < 1 || day > 31 || math.Trunc(day) != day {
			return errors.New("每月重置日须为 1 至 31 的整数；不足该日的月份按月末重置")
		}
	}
	if zone := text(row, "resetTimezone"); zone != "" {
		if _, err := time.LoadLocation(zone); err != nil {
			return errors.New("重置时区无效，请使用 Asia/Shanghai 等 IANA 时区")
		}
	}
	return nil
}
