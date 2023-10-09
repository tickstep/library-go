package requester

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/tickstep/library-go/expires"
	"github.com/tickstep/library-go/expires/cachemap"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type IPType string

const (
	// MaxDuration 最大的Duration
	MaxDuration = 1<<63 - 1

	// IPAny 任意IP，默认取第一个域名解析的结果
	IPAny IPType = "any"
	// IPv4 优先使用Ipv4的域名解析地址
	IPv4 IPType = "ipv4"
	// IPv6 优先使用Ipv6的域名解析地址
	IPv6 IPType = "ipv6"
)

var (
	localTCPAddrList = []*net.TCPAddr{}

	// ProxyAddr 代理地址
	ProxyAddr string

	// ErrProxyAddrEmpty 代理地址为空
	ErrProxyAddrEmpty = errors.New("proxy addr is empty")

	tcpCache = cachemap.GlobalCacheOpMap.LazyInitCachePoolOp("requester/tcp")

	// ipPref 域名解析策略
	ipPref = IPAny
)

// SetLocalTCPAddrList 设置网卡地址
func SetLocalTCPAddrList(ips ...string) {
	list := make([]*net.TCPAddr, 0, len(ips))
	for k := range ips {
		p := net.ParseIP(ips[k])
		if p == nil {
			continue
		}

		list = append(list, &net.TCPAddr{
			IP: p,
		})
	}
	localTCPAddrList = list
}

// SetPreferIPType 设置优先的IP类型
func SetPreferIPType(ipType IPType) {
	ipPref = ipType
}

func proxyFunc(req *http.Request) (*url.URL, error) {
	u, err := checkProxyAddr(ProxyAddr)
	if err != nil {
		return http.ProxyFromEnvironment(req)
	}

	return u, err
}

func getLocalTCPAddr() *net.TCPAddr {
	if len(localTCPAddrList) == 0 {
		return nil
	}
	i := mathrand.Intn(len(localTCPAddrList))
	return localTCPAddrList[i]
}

func getDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		LocalAddr: getLocalTCPAddr(),
		DualStack: true,
	}
}

func checkProxyAddr(proxyAddr string) (u *url.URL, err error) {
	if proxyAddr == "" {
		return nil, ErrProxyAddrEmpty
	}

	host, port, err := net.SplitHostPort(proxyAddr)
	if err == nil {
		u = &url.URL{
			Host: net.JoinHostPort(host, port),
		}
		return
	}

	u, err = url.Parse(proxyAddr)
	if err == nil {
		return
	}

	return
}

// SetGlobalProxy 设置代理
func SetGlobalProxy(proxyAddr string) {
	ProxyAddr = proxyAddr
}

// SetTCPHostBind 设置host绑定ip
func SetTCPHostBind(host, ip string) {
	tcpCache.Store(host, expires.NewDataExpires(net.ParseIP(ip), MaxDuration))
	return
}

func getServerName(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	return host
}

// resolveTCPHost
// 解析的tcpaddr没有port!!!
func resolveTCPHost(ctx context.Context, host string) (ip net.IP, err error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return
	}

	// 执行域名解析策略
	for _, ipaddr := range addrs {
		if ipPref == IPv4 { // 优先IPv4
			if isIPv4(ipaddr.IP.String()) {
				return ipaddr.IP, nil
			}
		} else if ipPref == IPv6 { // 优先IPv6
			if isIPv6(ipaddr.IP.String()) {
				return ipaddr.IP, nil
			}
		}
	}

	// 默认使用第一个解析结果
	return addrs[0].IP, nil
}

func isIPv4(ip string) bool {
	return strings.Contains(ip, ".")
}

func isIPv6(ip string) bool {
	return strings.Contains(ip, ":")
}

func dialContext(ctx context.Context, network, address string) (conn net.Conn, err error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
		host, portStr, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		data, err := cachemap.GlobalCacheOpMap.CacheOperationWithError("requester/tcp", host, func() (expires.DataExpires, error) {
			ip, err := resolveTCPHost(ctx, host)
			if err != nil {
				return nil, err
			}
			return expires.NewDataExpires(ip, 10*time.Minute), nil // 传值
		})
		if err != nil {
			return nil, err
		}

		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, err
		}

		return net.DialTCP(network, getLocalTCPAddr(), &net.TCPAddr{
			IP:   data.Data().(net.IP),
			Port: port, // 设置端口
		})
	}

	// 非 tcp 请求
	conn, err = getDialer().DialContext(ctx, network, address)
	return
}

func dial(network, address string) (conn net.Conn, err error) {
	return dialContext(context.Background(), network, address)
}

func (h *HTTPClient) dialTLSFunc() func(network, address string) (tlsConn net.Conn, err error) {
	return func(network, address string) (tlsConn net.Conn, err error) {
		conn, err := dialContext(context.Background(), network, address)
		if err != nil {
			return nil, err
		}

		return tls.Client(conn, &tls.Config{
			ServerName:         getServerName(address),
			InsecureSkipVerify: !h.https,
		}), nil
	}
}
