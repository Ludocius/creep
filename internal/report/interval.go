package report

import "math"

// z95 is the two-sided 95% normal quantile.
const z95 = 1.959963984540054

// wilson returns the 95% Wilson score interval for k successes in n trials,
// rounded to three decimals so every format prints the same numbers. Wilson
// rather than the normal approximation because calibration samples are
// small and often at 0 or n, where the normal interval collapses to a point.
// No trials means no information: [0, 1].
func wilson(k, n int) (low, high float64) {
	if n <= 0 {
		return 0, 1
	}
	p := float64(k) / float64(n)
	nf := float64(n)
	z2 := z95 * z95
	center := (p + z2/(2*nf)) / (1 + z2/nf)
	half := z95 / (1 + z2/nf) * math.Sqrt(p*(1-p)/nf+z2/(4*nf*nf))
	return round3(math.Max(0, center-half)), round3(math.Min(1, center+half))
}

func round3(x float64) float64 { return math.Round(x*1000) / 1000 }
