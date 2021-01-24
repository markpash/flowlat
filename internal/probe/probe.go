package probe

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang probe ../../bpf/probe.c -- -O3 -Wall -Werror -Wno-address-of-packed-member

func load() (*probeObjects, error) {
	probeSpecs, err := newProbeSpecs()
	if err != nil {
		return nil, err
	}

	objs, err := probeSpecs.Load(nil)
	if err != nil {
		return nil, err
	}
	return objs, nil
}
