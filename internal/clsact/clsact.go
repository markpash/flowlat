package clsact

import "github.com/vishvananda/netlink"

// ClsAct is a classifier action qdisc. Implements netlink.Qdisc.
type ClsAct struct {
	attrs *netlink.QdiscAttrs
}

// NewClsAct creates a new clsact qdisc given the qdisc attributes.
func NewClsAct(attrs *netlink.QdiscAttrs) *ClsAct {
	return &ClsAct{attrs: attrs}
}

// Attrs method returns the qdisc attributes.
func (qdisc *ClsAct) Attrs() *netlink.QdiscAttrs {
	return qdisc.attrs
}

// Type method returns the qdisc type.
func (qdisc *ClsAct) Type() string {
	return "clsact"
}
