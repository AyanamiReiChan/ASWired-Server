package httpapi

// defaultBehaviorLimits is the built-in policy for an absent or null global
// configuration. Explicit objects, including disabled or empty rules, remain
// authoritative. Return fresh values so settings projection cannot mutate the
// policy used by another request.
func defaultBehaviorLimits() map[string]any {
	return map[string]any{
		"enabled":       true,
		"maxGapSeconds": 15,
		"rules": []map[string]any{
			{
				"id": "balanced-long", "type": "sustained",
				"thresholdMbps": 80, "durationSeconds": 600,
				"limitMbps": 30, "penaltySeconds": 600,
				"priority": 10, "notify": false,
			},
			{
				"id": "balanced-high", "type": "sustained",
				"thresholdMbps": 200, "durationSeconds": 120,
				"limitMbps": 50, "penaltySeconds": 600,
				"priority": 20, "notify": false,
			},
		},
	}
}
