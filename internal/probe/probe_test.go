package probe

import (
	"testing"

	"github.com/markpash/flowlat/internal/packets"
	"github.com/markpash/flowlat/internal/tc"

	"github.com/stretchr/testify/require"
)

func TestTCPv4ACKPacket(t *testing.T) {
	require.NoError(t, setRlimit())
	probe := probe{}
	err := probe.loadObjects()
	require.NoError(t, err)

	in := packets.TCPv4ACK()
	ret, out, err := probe.bpfObjects.ProgramProbe.Test(in)
	require.NoError(t, err)
	require.Equal(t, tc.TCActOk, ret)
	require.Equal(t, in, out)
}

func TestTCPv4SYNPacket(t *testing.T) {
	require.NoError(t, setRlimit())
	probe := probe{}
	err := probe.loadObjects()
	require.NoError(t, err)

	in := packets.TCPv4SYN()
	ret, out, err := probe.bpfObjects.ProgramProbe.Test(in)
	require.NoError(t, err)
	require.Equal(t, tc.TCActOk, ret)
	require.Equal(t, in, out)
}

func TestTCPv4SYNACKPacket(t *testing.T) {
	require.NoError(t, setRlimit())
	probe := probe{}
	err := probe.loadObjects()
	require.NoError(t, err)

	in := packets.TCPv4SYNACK()
	ret, out, err := probe.bpfObjects.ProgramProbe.Test(in)
	require.NoError(t, err)
	require.Equal(t, tc.TCActOk, ret)
	require.Equal(t, in, out)
}
