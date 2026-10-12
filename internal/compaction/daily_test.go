package compaction

import (
	"testing"
	"time"
)

func TestExtractNewestFileTime(t *testing.T) {
	tests := []struct {
		name     string
		files    []string
		expected time.Time
	}{
		{
			name:     "empty list",
			files:    []string{},
			expected: time.Time{},
		},
		{
			name: "single file",
			files: []string{
				"default/metrics/2026/01/01/00/metrics_20260101_120000_123456789.parquet",
			},
			expected: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		},
		{
			name: "multiple files - newest first",
			files: []string{
				"default/metrics/2026/01/01/00/metrics_20260103_150000_123456789.parquet",
				"default/metrics/2026/01/01/01/metrics_20260102_120000_123456789.parquet",
				"default/metrics/2026/01/01/02/metrics_20260101_090000_123456789.parquet",
			},
			expected: time.Date(2026, 1, 3, 15, 0, 0, 0, time.UTC),
		},
		{
			name: "multiple files - newest last",
			files: []string{
				"default/metrics/2026/01/01/00/metrics_20260101_090000_123456789.parquet",
				"default/metrics/2026/01/01/01/metrics_20260102_120000_123456789.parquet",
				"default/metrics/2026/01/01/02/metrics_20260103_150000_123456789.parquet",
			},
			expected: time.Date(2026, 1, 3, 15, 0, 0, 0, time.UTC),
		},
		{
			name: "multiple files - newest in middle",
			files: []string{
				"default/metrics/2026/01/01/00/metrics_20260102_090000_123456789.parquet",
				"default/metrics/2026/01/01/01/metrics_20260103_150000_123456789.parquet",
				"default/metrics/2026/01/01/02/metrics_20260101_120000_123456789.parquet",
			},
			expected: time.Date(2026, 1, 3, 15, 0, 0, 0, time.UTC),
		},
		{
			name: "daily compacted file",
			files: []string{
				"default/metrics/2026/01/01/metrics_20260102_000000_daily.parquet",
			},
			expected: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
		},
		{
			name: "mixed hourly and daily files",
			files: []string{
				"default/metrics/2026/01/01/00/metrics_20260101_120000_123456789.parquet",
				"default/metrics/2026/01/01/01/metrics_20260101_130000_987654321.parquet",
				"default/metrics/2026/01/01/metrics_20260102_000000_daily.parquet",
			},
			expected: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
		},
		{
			name:     "batched hourly compacted output",
			files:    []string{"db/m/2026/01/01/00/m_20260101_130500_1767272700000000000_b1_compacted.parquet"},
			expected: time.Date(2026, 1, 1, 13, 5, 0, 0, time.UTC),
		},
		{
			name:     "batched daily output",
			files:    []string{"db/m/2026/01/01/m_20260101_000000_1767225600000000000_b12_daily.parquet"},
			expected: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:     "batched output with underscores in measurement",
			files:    []string{"db/cpu_load_avg/2026/01/01/00/cpu_load_avg_20260101_130500_1767272700000000000_b3_compacted.parquet"},
			expected: time.Date(2026, 1, 1, 13, 5, 0, 0, time.UTC),
		},
		{
			name:     "batched output with rewrite suffix",
			files:    []string{"db/m/2026/01/01/00/m_20260101_130500_1767272700000000000_b1_compacted_rewrite_42.parquet"},
			expected: time.Date(2026, 1, 1, 13, 5, 0, 0, time.UTC),
		},
		{
			name:     "legacy compacted without nanos",
			files:    []string{"db/m/2026/01/01/00/m_20260101_130500_compacted.parquet"},
			expected: time.Date(2026, 1, 1, 13, 5, 0, 0, time.UTC),
		},
		{
			name:     "legacy compacted with nanos, no batch",
			files:    []string{"db/m/2026/01/01/00/m_20260101_130500_123456789_compacted.parquet"},
			expected: time.Date(2026, 1, 1, 13, 5, 0, 0, time.UTC),
		},
		{
			name:     "legacy daily date only",
			files:    []string{"db/m/2026/01/01/m_20260102_daily.parquet"},
			expected: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
		},
		{
			name: "invalid filename format",
			files: []string{
				"default/metrics/2026/01/01/00/invalid.parquet",
				"default/metrics/2026/01/01/01/no_timestamp.parquet",
			},
			expected: time.Time{},
		},
		{
			name: "mixed valid and invalid",
			files: []string{
				"default/metrics/2026/01/01/00/invalid.parquet",
				"default/metrics/2026/01/01/01/metrics_20260102_120000_123456789.parquet",
				"default/metrics/2026/01/01/02/no_timestamp.parquet",
			},
			expected: time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractNewestFileTime(tt.files)
			if !result.Equal(tt.expected) {
				t.Errorf("extractNewestFileTime() = %v, want %v", result, tt.expected)
			}
		})
	}
}
