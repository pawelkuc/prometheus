// Copyright 2018 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package unittest

import (
	"bytes"
	"encoding/base64"
	"io"
	"testing"
	"time"

	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/promqltest"
)

var (
	unittest1 = []byte(`rule_files:
  - rules.yml

evaluation_interval: 1m

tests:
  # Basic tests for promql_expr_test, not dependent on rules.
  - interval: 1m
    input_series:
      - series: test_full
        values: "0 0"

      - series: test_repeat
        values: "1x2"

      - series: test_increase
        values: "1+1x2"

      - series: test_histogram
        values: "{{schema:1 sum:-0.3 count:32.1 z_bucket:7.1 z_bucket_w:0.05 buckets:[5.1 10 7] offset:-3 n_buckets:[4.1 5] n_offset:-5}}"

      - series: test_histogram_repeat
        values: "{{sum:3 count:2 buckets:[2]}}x2"

      - series: test_histogram_increase
        values: "{{sum:3 count:2 buckets:[2]}}+{{sum:1.3 count:1 buckets:[1]}}x2"

      - series: test_stale
        values: "0 stale"

      - series: test_missing
        values: "0 _ _ _ _ _ _ 0"

    promql_expr_test:
      # Ensure the sample is evaluated at the time we expect it to be.
      - expr: timestamp(test_full)
        eval_time: 0m
        exp_samples:
          - value: 0
      - expr: timestamp(test_full)
        eval_time: 1m
        exp_samples:
          - value: 60
      - expr: timestamp(test_full)
        eval_time: 2m
        exp_samples:
          - value: 60

      # Repeat & increase
      - expr: test_repeat
        eval_time: 2m
        exp_samples:
          - value: 1
            labels: "test_repeat"
      - expr: test_increase
        eval_time: 2m
        exp_samples:
          - value: 3
            labels: "test_increase"

      # Histograms
      - expr: test_histogram
        eval_time: 1m
        exp_samples:
          - labels: "test_histogram"
            histogram: "{{schema:1 sum:-0.3 count:32.1 z_bucket:7.1 z_bucket_w:0.05 buckets:[5.1 10 7] offset:-3 n_buckets:[4.1 5] n_offset:-5}}"

      - expr: test_histogram_repeat
        eval_time: 2m
        exp_samples:
          - labels: "test_histogram_repeat"
            histogram: "{{count:2 sum:3 buckets:[2]}}"

      - expr: test_histogram_increase
        eval_time: 2m
        exp_samples:
          - labels: "test_histogram_increase"
            histogram: "{{count:4 sum:5.6 buckets:[4]}}"

      # Ensure a value is stale as soon as it is marked as such.
      - expr: test_stale
        eval_time: 59s
        exp_samples:
          - value: 0
            labels: "test_stale"
      - expr: test_stale
        eval_time: 1m
        exp_samples: []

      # Ensure lookback delta is respected, when a value is missing.
      - expr: timestamp(test_missing)
        eval_time: 5m
        exp_samples:
          - value: 0
      - expr: timestamp(test_missing)
        eval_time: 5m1s
        exp_samples: []

  # Minimal test case to check edge case of a single sample.
  - input_series:
      - series: test
        values: 1

    promql_expr_test:
      - expr: test
        eval_time: 0
        exp_samples:
          - value: 1
            labels: test

  # Test recording rules run even if input_series isn't provided.
  - promql_expr_test:
      - expr: count_over_time(fixed_data[1h])
        eval_time: 1h
        exp_samples:
          - value: 61
      - expr: timestamp(fixed_data)
        eval_time: 1h
        exp_samples:
          - value: 3600

  # Tests for alerting rules.
  - interval: 1m
    input_series:
      - series: 'up{job="prometheus", instance="localhost:9090"}'
        values: "0+0x1440"

    promql_expr_test:
      - expr: count(ALERTS) by (alertname, alertstate)
        eval_time: 4m
        exp_samples:
          - labels: '{alertname="AlwaysFiring",alertstate="firing"}'
            value: 1
          - labels: '{alertname="InstanceDown",alertstate="pending"}'
            value: 1

    alert_rule_test:
      - eval_time: 1d
        alertname: AlwaysFiring
        exp_alerts:
          - {}

      - eval_time: 1d
        alertname: InstanceDown
        exp_alerts:
          - exp_labels:
              severity: page
              instance: localhost:9090
              job: prometheus
            exp_annotations:
              summary: "Instance localhost:9090 down"
              description: "localhost:9090 of job prometheus has been down for more than 5 minutes."

      - eval_time: 0
        alertname: AlwaysFiring
        exp_alerts:
          - {}

      - eval_time: 0
        alertname: InstanceDown
        exp_alerts: []

  # Tests for interval vs evaluation_interval.
  - interval: 1s
    input_series:
      - series: 'test{job="test", instance="x:0"}'
        # 2 minutes + 1 second of input data, recording rules should only run
        # once a minute.
        values: "0+1x120"

    promql_expr_test:
      - expr: job:test:count_over_time1m
        eval_time: 0m
        exp_samples:
          - value: 1
            labels: 'job:test:count_over_time1m{job="test"}'
      - expr: timestamp(job:test:count_over_time1m)
        eval_time: 10s
        exp_samples:
          - value: 0
            labels: '{job="test"}'

      - expr: job:test:count_over_time1m
        eval_time: 1m
        exp_samples:
          - value: 61
            labels: 'job:test:count_over_time1m{job="test"}'
      - expr: timestamp(job:test:count_over_time1m)
        eval_time: 1m10s
        exp_samples:
          - value: 60
            labels: '{job="test"}'

      - expr: job:test:count_over_time1m
        eval_time: 2m
        exp_samples:
          - value: 61
            labels: 'job:test:count_over_time1m{job="test"}'
      - expr: timestamp(job:test:count_over_time1m)
        eval_time: 2m59s999ms
        exp_samples:
          - value: 120
            labels: '{job="test"}'`)
)

func TestRulesUnitTest(t *testing.T) {
	var output bytes.Buffer
	encoder := base64.NewEncoder(base64.StdEncoding, &output)
	encoder.Write(unittest1)
	encoder.Close()

	type args struct {
		rules []io.Reader
	}
	tests := []struct {
		name      string
		args      args
		queryOpts promqltest.LazyLoaderOpts
		want      int
	}{
		{
			name: "Passing Unit Tests",
			args: args{
				rules: []io.Reader{&output},
			},
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RulesUnitTest(tt.queryOpts, nil, false, tt.args.rules...); got != tt.want {
				t.Errorf("RulesUnitTest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRulesUnitTest2(t *testing.T) {
	type args struct {
		utfs []UnitTestFile
	}
	tests := []struct {
		name      string
		args      args
		queryOpts promqltest.LazyLoaderOpts
		want      int
	}{
		{
			name: "Passing Unit Tests",
			args: args{
				utfs: []UnitTestFile{
					{
						RuleFiles:          []string{""},
						EvaluationInterval: model.Duration(time.Second),
						GroupEvalOrder:     []string{""},
						Tests: []TestGroup{
							{
								Interval: model.Duration(time.Second),
								InputSeries: []Series{
									{
										Series: "",
										Values: "",
									},
								},
								AlertRuleTests:  []AlertTestCase{},
								PromqlExprTests: []PromqlTestCase{},
								ExternalLabels:  labels.Labels{},
								ExternalURL:     "",
								TestGroupName:   "testgroup1",
							},
						},
					},
				},
			},
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RulesUnitTest2(tt.queryOpts, nil, false, tt.args.utfs...); got != tt.want {
				t.Errorf("RulesUnitTest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRulesUnitTestRun(t *testing.T) {
	type args struct {
		run   []string
		files []string
	}
	tests := []struct {
		name      string
		args      args
		queryOpts promqltest.LazyLoaderOpts
		want      int
	}{
		{
			name: "Test all without run arg",
			args: args{
				run:   nil,
				files: []string{"../testdata/rules_run.yml"},
			},
			want: 1,
		},
		{
			name: "Test all with run arg",
			args: args{
				run:   []string{"correct", "wrong"},
				files: []string{"../testdata/rules_run.yml"},
			},
			want: 1,
		},
		{
			name: "Test correct",
			args: args{
				run:   []string{"correct"},
				files: []string{"../testdata/rules_run.yml"},
			},
			want: 0,
		},
		{
			name: "Test wrong",
			args: args{
				run:   []string{"wrong"},
				files: []string{"../testdata/rules_run.yml"},
			},
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// TODO: temporary remove
			// got := RulesUnitTest(tt.queryOpts, tt.args.run, false, tt.args.files...)
			// require.Equal(t, tt.want, got)
		})
	}
}
