package outbound

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
)

type Cmcc struct {
	*Base
	option *CmccOption
	user   string
	pass   string
}

type CmccOption struct {
	BasicOption
	Name     string `proxy:"name"`
	Server   string `proxy:"server"`
	Port     int    `proxy:"port"`
	UserName string `proxy:"username,omitempty"`
	Password string `proxy:"password,omitempty"`
	UDP      bool   `proxy:"udp,omitempty"`
	AuthType string `proxy:"auth-type,omitempty"`
}

type xorConn struct {
	net.Conn
}

func (c *xorConn) Write(b []byte) (n int, err error) {
	obfs := make([]byte, len(b))
	for i := range b {
		obfs[i] = b[i] ^ 0xFF
	}
	return c.Conn.Write(obfs)
}

func (c *Cmcc) clientHandshakeContext(ctx context.Context, conn net.Conn, addr socks5.Addr, command socks5.Command) (socks5.Addr, error) {
	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, conn)
		defer done(nil)
	}

	rw := &xorConn{Conn: conn}

	var err error
	buf := make([]byte, socks5.MaxAddrLen)

	authMethod := byte(0x82)
	if c.option.AuthType == "0x80" || c.option.AuthType == "80" {
		authMethod = 0x80
	}

	if _, err = rw.Write([]byte{5, 1, authMethod}); err != nil {
		return nil, err
	}

	if authMethod == 0x80 {
		challenge := make([]byte, 2)
		if _, err := io.ReadFull(conn, challenge); err != nil {
			return nil, err
		}

		if challenge[0] != 5 {
			return nil, errors.New("cmcc SOCKS version error")
		}

		mac := hmac.New(sha256.New, []byte(c.user+c.pass))
		mac.Write(challenge[1:])
		signature := mac.Sum(nil)

		authMsg := make([]byte, 0, 1+1+len(c.user)+1+32)
		authMsg = append(authMsg, 1, byte(len(c.user)))
		authMsg = append(authMsg, []byte(c.user)...)
		authMsg = append(authMsg, 0x20)
		authMsg = append(authMsg, signature...)

		if _, err := rw.Write(authMsg); err != nil {
			return nil, err
		}
	} else {
		challenge := make([]byte, 6)
		if _, err := io.ReadFull(conn, challenge); err != nil {
			return nil, err
		}

		if challenge[0] != 5 || challenge[1] != 0x82 {
			return nil, errors.New("cmcc SOCKS version/method error")
		}

		passMd5 := md5.Sum([]byte(c.pass))
		passMd5Hex := hex.EncodeToString(passMd5[:])
		mac := hmac.New(sha256.New, []byte(c.user+passMd5Hex))
		mac.Write(challenge[2:])
		signature := mac.Sum(nil)

		// The fixed data based on the reversed payload
		fixData, _ := hex.DecodeString("140101010204000000000302271004010105020004")

		authMsg := make([]byte, 0, 1+1+len(c.user)+1+32+21)
		authMsg = append(authMsg, 1, byte(len(c.user)))
		authMsg = append(authMsg, []byte(c.user)...)
		authMsg = append(authMsg, 0x20)
		authMsg = append(authMsg, signature...)
		authMsg = append(authMsg, fixData...)

		if _, err := rw.Write(authMsg); err != nil {
			return nil, err
		}
	}

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return nil, err
	}
	if buf[1] != 0 {
		return nil, errors.New("cmcc rejected username/password")
	}

	req := bytes.Join([][]byte{{5, command, 0}, addr}, nil)
	if _, err := rw.Write(req); err != nil {
		return nil, err
	}

	if _, err := io.ReadFull(conn, buf[:3]); err != nil {
		return nil, err
	}

	if buf[1] != 0 {
		return nil, fmt.Errorf("cmcc connect failed, rep: 0x%02x", buf[1])
	}

	return socks5.ReadAddr(conn, buf)
}

func (c *Cmcc) StreamConnContext(ctx context.Context, conn net.Conn, metadata *C.Metadata) (net.Conn, error) {
	if _, err := c.clientHandshakeContext(ctx, conn, serializesSocksAddr(metadata), socks5.CmdConnect); err != nil {
		return nil, err
	}
	return &xorConn{Conn: conn}, nil
}

func (c *Cmcc) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	conn, err := c.dialer.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", c.addr, err)
	}

	defer func(conn net.Conn) {
		safeConnClose(conn, err)
	}(conn)

	conn, err = c.StreamConnContext(ctx, conn, metadata)
	if err != nil {
		return nil, err
	}

	return NewConn(conn, c), nil
}

func (c *Cmcc) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = c.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}

	conn, err := c.dialer.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		err = fmt.Errorf("%s connect error: %w", c.addr, err)
		return
	}

	defer func(conn net.Conn) {
		safeConnClose(conn, err)
	}(conn)

	udpAssocateAddr := socks5.AddrFromStdAddrPort(netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
	bindAddr, err := c.clientHandshakeContext(ctx, conn, udpAssocateAddr, socks5.CmdUDPAssociate)
	if err != nil {
		err = fmt.Errorf("client handshake error: %w", err)
		return
	}

	bindUDPAddr := bindAddr.UDPAddr()
	if bindUDPAddr == nil {
		err = errors.New("invalid UDP bind address")
		return
	} else if bindUDPAddr.IP.IsUnspecified() {
		serverAddr, err := resolveUDPAddr(ctx, "udp", c.Addr(), C.IPv4Prefer)
		if err != nil {
			return nil, err
		}
		bindUDPAddr.IP = serverAddr.IP
	}

	pc, err := c.dialer.ListenPacket(ctx, "udp", "", bindUDPAddr.AddrPort())
	if err != nil {
		return
	}

	go func() {
		io.Copy(io.Discard, conn)
		conn.Close()
		pc.Close()
	}()

	return newPacketConn(&cmccPacketConn{PacketConn: pc, rAddr: bindUDPAddr, tcpConn: conn}, c), nil
}

type cmccPacketConn struct {
	net.PacketConn
	rAddr   net.Addr
	tcpConn net.Conn
}

func (uc *cmccPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	packet, err := socks5.EncodeUDPPacket(socks5.ParseAddrToSocksAddr(addr), b)
	if err != nil {
		return
	}

	// XOR obfuscate UDP packet before sending
	for i := range packet {
		packet[i] ^= 0xFF
	}

	return uc.PacketConn.WriteTo(packet, uc.rAddr)
}

func (uc *cmccPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, _, e := uc.PacketConn.ReadFrom(b)
	if e != nil {
		return 0, nil, e
	}

	addr, payload, err := socks5.DecodeUDPPacket(b[:n])
	if err != nil {
		return 0, nil, err
	}

	udpAddr := addr.UDPAddr()
	if udpAddr == nil {
		return 0, nil, errors.New("parse udp addr error")
	}

	copy(b, payload)
	return n - len(addr) - 3, udpAddr, nil
}

func (uc *cmccPacketConn) Close() error {
	uc.tcpConn.Close()
	return uc.PacketConn.Close()
}

func (c *Cmcc) ProxyInfo() C.ProxyInfo {
	info := c.Base.ProxyInfo()
	info.DialerProxy = c.option.DialerProxy
	return info
}

func NewCmcc(option CmccOption) (*Cmcc, error) {
	outbound := &Cmcc{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			Type:         C.Cmcc,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
		user:   option.UserName,
		pass:   option.Password,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	return outbound, nil
}
