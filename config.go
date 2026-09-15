// Copyright (c) 2026 Parrish Lyon. All rights reserved.
// SENTINELGO | Parrish Lyon | PL-SENTINELGO-20260914
package sentinelgo

import (
	"fmt"
	"maps"
	"math"
)

// Config is copied per analysis. Updates never change an in-flight request.
type Config struct {
	VelocityWindowMinutes       int            `json:"velocity_window_minutes"`
	VelocityMinAttempts         int            `json:"velocity_min_attempts"`
	VelocityMaxAvgValue         float64        `json:"velocity_max_avg_value"`
	ATOWindowHours              int            `json:"ato_window_hours"`
	BINAttackIPMin              int            `json:"bin_attack_ip_min"`
	BINAttackCardMin            int            `json:"bin_attack_card_min"`
	BINAttackVelocityMultiplier float64        `json:"bin_attack_velocity_multiplier"`
	DeviceManyUsersThreshold    int            `json:"device_many_users_threshold"`
	DeviceMinUsersForFlag       int            `json:"device_min_users_for_flag"`
	ClusterTimeWindowHours      int            `json:"cluster_time_window_hours"`
	IPClusterMinTxns            int            `json:"ip_cluster_min_txns"`
	IPClusterMinUsers           int            `json:"ip_cluster_min_users"`
	CardClusterMinTxns          int            `json:"card_cluster_min_txns"`
	RiskWeights                 map[string]int `json:"risk_weights"`
	GradeThresholds             map[string]int `json:"grade_thresholds"`
}

func DefaultConfig() Config {
	return Config{10, 5, 20, 1, 10, 8, 2, 20, 15, 2, 3, 2, 8,
		map[string]int{"very_large_amount": 2, "large_amount": 1, "card_testing": 4, "ato_attempt": 3, "bin_attack": 2, "synthetic_email": 1, "vpn_ip": 1, "device_shared": 1, "critical_cluster": 3, "high_cluster": 1},
		map[string]int{"CRITICAL RISK": 6, "INVESTIGATE": 4, "HIGH RISK": 2, "LOW RISK": 0}}
}
func (c Config) Clone() Config {
	c.RiskWeights = maps.Clone(c.RiskWeights)
	c.GradeThresholds = maps.Clone(c.GradeThresholds)
	return c
}
func (c Config) Validate() error {
	for _, v := range []int{c.VelocityWindowMinutes, c.VelocityMinAttempts, c.ATOWindowHours, c.BINAttackIPMin, c.BINAttackCardMin, c.DeviceManyUsersThreshold, c.DeviceMinUsersForFlag, c.ClusterTimeWindowHours, c.IPClusterMinTxns, c.IPClusterMinUsers, c.CardClusterMinTxns} {
		if v < 1 || v > 1000000 {
			return fmt.Errorf("integer thresholds must be between 1 and 1000000")
		}
	}
	for _, v := range []float64{c.VelocityMaxAvgValue, c.BINAttackVelocityMultiplier} {
		if math.IsNaN(v) || math.IsInf(v, 0) || v <= 0 || v > 1e9 {
			return fmt.Errorf("numeric thresholds must be finite, positive and <= 1000000000")
		}
	}
	d := DefaultConfig()
	if len(c.RiskWeights) != len(d.RiskWeights) || len(c.GradeThresholds) != 4 {
		return fmt.Errorf("all supported risk weights and grade thresholds are required")
	}
	for k := range d.RiskWeights {
		v, ok := c.RiskWeights[k]
		if !ok || v < 0 || v > 1000 {
			return fmt.Errorf("invalid risk weight: %s", k)
		}
	}
	for k := range d.GradeThresholds {
		v, ok := c.GradeThresholds[k]
		if !ok || v < 0 || v > 1000000 {
			return fmt.Errorf("invalid grade: %s", k)
		}
	}
	g := c.GradeThresholds
	if !(g["CRITICAL RISK"] > g["INVESTIGATE"] && g["INVESTIGATE"] > g["HIGH RISK"] && g["HIGH RISK"] > g["LOW RISK"] && g["LOW RISK"] == 0) {
		return fmt.Errorf("grades must follow source order: CRITICAL > INVESTIGATE > HIGH > LOW=0")
	}
	return nil
}

// ModeConfig preserves the source demo presets; other custom settings survive.
func ModeConfig(c Config, demo bool) Config {
	c = c.Clone()
	d := DefaultConfig()
	if demo {
		d.VelocityMinAttempts = 3
		d.VelocityMaxAvgValue = 30
		d.BINAttackIPMin = 5
		d.BINAttackCardMin = 4
		d.DeviceManyUsersThreshold = 10
		d.RiskWeights["card_testing"] = 5
		d.RiskWeights["ato_attempt"] = 4
		d.RiskWeights["bin_attack"] = 3
		d.RiskWeights["vpn_ip"] = 2
		d.RiskWeights["device_shared"] = 2
		d.GradeThresholds = map[string]int{"CRITICAL RISK": 5, "INVESTIGATE": 3, "HIGH RISK": 1, "LOW RISK": 0}
	}
	c.VelocityMinAttempts = d.VelocityMinAttempts
	c.VelocityMaxAvgValue = d.VelocityMaxAvgValue
	c.BINAttackIPMin = d.BINAttackIPMin
	c.BINAttackCardMin = d.BINAttackCardMin
	c.DeviceManyUsersThreshold = d.DeviceManyUsersThreshold
	for _, k := range []string{"card_testing", "ato_attempt", "bin_attack", "vpn_ip", "device_shared"} {
		c.RiskWeights[k] = d.RiskWeights[k]
	}
	c.GradeThresholds = d.GradeThresholds
	return c
}
