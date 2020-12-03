package libauditgo

type record struct {
	syscallNum string
	arch       string
	a0         int
	a1         int
}
