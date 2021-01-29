package probe

import (
	"context"

	"github.com/markpash/flowlat/internal/clsact"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang probe ../../bpf/probe.c -- -O3 -Wall -Werror -Wno-address-of-packed-member

type probe struct {
	iface      netlink.Link
	handle     *netlink.Handle
	qdisc      *clsact.ClsAct
	filters    []*netlink.BpfFilter
	bpfObjects *probeObjects
}

// Run runs the probe on the given interface.
func Run(ctx context.Context, iface netlink.Link) error {
	probe, err := newProbe(iface)
	if err != nil {
		return err
	}

	<-ctx.Done()

	if err := probe.Close(); err != nil {
		return err
	}

	return nil
}

func (p *probe) Close() error {
	if err := p.handle.QdiscDel(p.qdisc); err != nil {
		return err
	}

	for _, filter := range p.filters {
		if err := p.handle.FilterDel(filter); err != nil {
			return err
		}
	}

	if err := p.bpfObjects.Close(); err != nil {
		return err
	}

	p.handle.Delete()
	return nil
}

func newProbe(iface netlink.Link) (*probe, error) {
	handle, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}

	probe := probe{
		iface:  iface,
		handle: handle,
	}

	if err := probe.loadObjects(); err != nil {
		return nil, err
	}

	if err := probe.createQdisc(); err != nil {
		return nil, err
	}

	if err := probe.createFilters(); err != nil {
		return nil, err
	}

	return &probe, nil
}

func (p *probe) createQdisc() error {
	p.qdisc = clsact.NewClsAct(&netlink.QdiscAttrs{
		LinkIndex: p.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	})

	if err := p.handle.QdiscAdd(p.qdisc); err != nil {
		return err
	}
	return nil
}

func (p *probe) createFilters() error {
	addFilter := func(attrs netlink.FilterAttrs) {
		p.filters = append(p.filters, &netlink.BpfFilter{
			FilterAttrs:  attrs,
			DirectAction: true,
			Fd:           p.bpfObjects.ProgramProbe.FD(),
		})
	}

	// Ingress IPv4
	addFilter(netlink.FilterAttrs{
		LinkIndex: p.iface.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Protocol:  unix.ETH_P_IP,
	})

	// Egress IPv4
	addFilter(netlink.FilterAttrs{
		LinkIndex: p.iface.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Protocol:  unix.ETH_P_IP,
	})

	for _, filter := range p.filters {
		if err := p.handle.FilterReplace(filter); err != nil {
			return err
		}
	}

	return nil
}

func (p *probe) loadObjects() error {
	probeSpecs, err := newProbeSpecs()
	if err != nil {
		return err
	}

	objs, err := probeSpecs.Load(nil)
	if err != nil {
		return err
	}

	p.bpfObjects = objs
	return nil
}
