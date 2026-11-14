package calibrate

import (
	"math"
	"math/big"
)

// wilsonZ is the normal quantile of the 95% Wilson interval, 1.96, kept as
// the exact fraction 49/25 so tier decisions can compare without rounding.
const (
	wilsonZNum = 49
	wilsonZDen = 25
)

// Score is how many tasks the model answered correctly, with the 95% Wilson
// score interval for its true rate. Total 0 means not measured: the interval
// is then [0, 1].
type Score struct {
	Correct int     `json:"correct"`
	Total   int     `json:"total"`
	Lower   float64 `json:"lower"`
	Upper   float64 `json:"upper"`
}

// ClassScore is the Score over one class's tasks, vulnerable and safe.
type ClassScore struct {
	Class Class `json:"class"`
	Score
}

func newScore(correct, total int) Score {
	lo, hi := wilson(correct, total)
	return Score{Correct: correct, Total: total, Lower: lo, Upper: hi}
}

// wilson returns the 95% Wilson score interval for correct out of total.
// It is for display; tier rules use lowerAtLeast, which is exact.
func wilson(correct, total int) (float64, float64) {
	if total <= 0 {
		return 0, 1
	}
	n := float64(total)
	p := float64(correct) / n
	z := float64(wilsonZNum) / wilsonZDen
	z2 := z * z
	den := 1 + z2/n
	center := (p + z2/(2*n)) / den
	half := z * math.Sqrt(p*(1-p)/n+z2/(4*n*n)) / den
	return math.Max(0, center-half), math.Min(1, center+half)
}

// lowerAtLeast reports whether the Wilson lower bound of correct/total is at
// least t, in exact rational arithmetic, so a tier never depends on float
// rounding or on the platform. With p = correct/total and z = 49/25, the
// bound is at least t exactly when A = p + z²/2n − t(1 + z²/n) is not
// negative and A² ≥ z²(p(1−p)/n + z²/4n²).
func lowerAtLeast(correct, total int, t *big.Rat) bool {
	if t.Sign() <= 0 {
		return true
	}
	if total <= 0 || correct <= 0 {
		return false
	}
	n := big.NewRat(int64(total), 1)
	p := big.NewRat(int64(correct), int64(total))
	z2 := big.NewRat(wilsonZNum*wilsonZNum, wilsonZDen*wilsonZDen)
	z2n := new(big.Rat).Quo(z2, n)

	a := new(big.Rat).Add(p, half(z2n))
	a.Sub(a, new(big.Rat).Mul(t, new(big.Rat).Add(big.NewRat(1, 1), z2n)))
	if a.Sign() < 0 {
		return false
	}
	q := new(big.Rat).Sub(big.NewRat(1, 1), p)
	d := new(big.Rat).Quo(new(big.Rat).Mul(p, q), n)
	d.Add(d, new(big.Rat).Quo(z2n, new(big.Rat).Mul(n, big.NewRat(4, 1))))
	d.Mul(d, z2)
	return new(big.Rat).Mul(a, a).Cmp(d) >= 0
}

func half(r *big.Rat) *big.Rat {
	return new(big.Rat).Quo(r, big.NewRat(2, 1))
}

// scoreClasses returns one ClassScore per calibrated class, in Classes
// order, and the overall Score. A class with no tasks gets Total 0.
func scoreClasses(tasks []Task, correct []bool) ([]ClassScore, Score) {
	right := map[Class]int{}
	total := map[Class]int{}
	all := 0
	for i, task := range tasks {
		total[task.Class]++
		if correct[i] {
			right[task.Class]++
			all++
		}
	}
	scores := make([]ClassScore, 0, len(Classes()))
	for _, c := range Classes() {
		scores = append(scores, ClassScore{Class: c, Score: newScore(right[c], total[c])})
	}
	return scores, newScore(all, len(tasks))
}
