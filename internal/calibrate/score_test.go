package calibrate

import (
	"math"
	"math/big"
	"testing"
)

func TestWilson(t *testing.T) {
	tests := []struct {
		name           string
		correct, total int
		lower, upper   float64
	}{
		{"no tasks", 0, 0, 0, 1},
		{"negative total", 0, -1, 0, 1},
		{"all wrong", 0, 10, 0, 0.2775},
		{"all right of 8", 8, 8, 0.6756, 1},
		{"13 of 14", 13, 14, 0.6853, 0.9873},
		{"half of 100", 50, 100, 0.4038, 0.5962},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lo, hi := wilson(tt.correct, tt.total)
			if math.Abs(lo-tt.lower) > 1e-4 || math.Abs(hi-tt.upper) > 1e-4 {
				t.Errorf("wilson(%d, %d) = [%.4f, %.4f], want [%.4f, %.4f]", tt.correct, tt.total, lo, hi, tt.lower, tt.upper)
			}
		})
	}
}

func TestLowerAtLeast(t *testing.T) {
	// For k = n the lower bound is exactly n/(n+z²); with z = 49/25 and
	// n = 8 that is 5000/7401, so this pair is an exact tie.
	tie := big.NewRat(5000, 7401)
	above := new(big.Rat).Add(tie, big.NewRat(1, 1_000_000_000))
	tests := []struct {
		name           string
		correct, total int
		t              *big.Rat
		want           bool
	}{
		{"zero threshold, no tasks", 0, 0, new(big.Rat), true},
		{"no tasks", 0, 0, big.NewRat(1, 100), false},
		{"all wrong", 0, 50, big.NewRat(1, 1000), false},
		{"exact tie passes", 8, 8, tie, true},
		{"just above the tie fails", 8, 8, above, false},
		{"one is out of reach", 1000, 1000, big.NewRat(1, 1), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := lowerAtLeast(tt.correct, tt.total, tt.t); got != tt.want {
				t.Errorf("lowerAtLeast(%d, %d, %s) = %v", tt.correct, tt.total, tt.t, got)
			}
		})
	}
}

// The exact comparison agrees with the float interval wherever the float
// is not within rounding of the threshold, for every tier threshold.
func TestLowerAtLeastMatchesWilson(t *testing.T) {
	for _, th := range []*big.Rat{big.NewRat(1, 4), big.NewRat(1, 2), big.NewRat(11, 20), big.NewRat(3, 4)} {
		f, _ := th.Float64()
		for n := 1; n <= 120; n++ {
			for k := 0; k <= n; k++ {
				lo, _ := wilson(k, n)
				if math.Abs(lo-f) < 1e-9 {
					continue
				}
				if got := lowerAtLeast(k, n, th); got != (lo >= f) {
					t.Fatalf("k=%d n=%d t=%s: exact %v, float lower %.6f", k, n, th, got, lo)
				}
			}
		}
	}
}

// The counts tierRules' comment states: what a class of 14 or 8 tasks
// needs for L (1/2) and M (1/4), and that half right over 100 tasks, or
// over a class of 8, is not enough for M.
func TestTierThresholdCounts(t *testing.T) {
	tests := []struct {
		total, l, m int
	}{{14, 11, 7}, {8, 7, 5}}
	for _, tt := range tests {
		if minCorrect(tt.total, big.NewRat(1, 2)) != tt.l || minCorrect(tt.total, big.NewRat(1, 4)) != tt.m {
			t.Errorf("n=%d needs %d for L and %d for M, want %d and %d", tt.total,
				minCorrect(tt.total, big.NewRat(1, 2)), minCorrect(tt.total, big.NewRat(1, 4)), tt.l, tt.m)
		}
	}
	if lowerAtLeast(4, 8, big.NewRat(1, 4)) || lowerAtLeast(50, 100, big.NewRat(11, 20)) {
		t.Error("half right reaches an M floor")
	}
}

func minCorrect(total int, th *big.Rat) int {
	for k := 0; k <= total; k++ {
		if lowerAtLeast(k, total, th) {
			return k
		}
	}
	return -1
}

func TestScoreClassesWithNoTasks(t *testing.T) {
	classes, overall := scoreClasses(nil, nil)
	if overall != (Score{Lower: 0, Upper: 1}) || len(classes) != len(Classes()) {
		t.Fatalf("overall %+v, %d classes", overall, len(classes))
	}
	for _, c := range classes {
		if c.Total != 0 || c.Lower != 0 || c.Upper != 1 {
			t.Errorf("%s = %+v, want unmeasured", c.Class, c.Score)
		}
	}
}

func TestJudge(t *testing.T) {
	vuln := Task{Class: ClassSSRF, Vulnerable: true, Line: 10}
	safe := Task{Class: ClassSSRF, Vulnerable: false, Line: 10}
	tests := []struct {
		name string
		task Task
		a    taskAnswer
		want bool
	}{
		{"safe twin called safe", safe, taskAnswer{Class: classNone}, true},
		{"safe twin flagged same class", safe, taskAnswer{Vulnerable: true, Class: "ssrf", Line: 10}, false},
		{"safe twin flagged other class", safe, taskAnswer{Vulnerable: true, Class: "sqli", Line: 3}, false},
		{"exact line", vuln, taskAnswer{Vulnerable: true, Class: "ssrf", Line: 10}, true},
		{"source line above", vuln, taskAnswer{Vulnerable: true, Class: "ssrf", Line: 8}, true},
		{"two below", vuln, taskAnswer{Vulnerable: true, Class: "ssrf", Line: 12}, true},
		{"three above", vuln, taskAnswer{Vulnerable: true, Class: "ssrf", Line: 7}, false},
		{"three below", vuln, taskAnswer{Vulnerable: true, Class: "ssrf", Line: 13}, false},
		{"wrong class", vuln, taskAnswer{Vulnerable: true, Class: "idor", Line: 10}, false},
		{"missed", vuln, taskAnswer{Class: classNone}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := judge(tt.task, tt.a); got != tt.want {
				t.Errorf("judge = %v, want %v", got, tt.want)
			}
		})
	}
}
