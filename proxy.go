/**
 *
 * @author Khanh Pham <mrpk1906@gmail.com>
 *
 */
package main

import (
	"bytes"
	"context"
	"github.com/rs/zerolog/log"
	"io"
	"net"
	"regexp"
	"sync"
	"time"
)

var (
	mu                  sync.RWMutex
	socketAuthenticated = make(map[string]string)
)

const (
	/* Buffer size to handle data from socket */
	BufferSize = 16 * 1024
)

// DialProxy implements Target by dialing a new connection to Addr
// and then proxying data back and forth.
//
// The To func is a shorthand way of creating a DialProxy.
type DialProxy struct {
	// Addr is the TCP address to proxy to.
	Addr string

	// KeepAlivePeriod sets the period between TCP keep alives.
	// If zero, a default is used. To disable, use a negative number.
	// The keep-alive is used for both the client connection and
	KeepAlivePeriod time.Duration

	// DialTimeout optionally specifies a dial timeout.
	// If zero, a default is used.
	// If negative, the timeout is disabled.
	DialTimeout time.Duration

	// DialContext optionally specifies an alternate dial function
	// for TCP targets. If nil, the standard
	// net.Dialer.DialContext method is used.
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)

	// OnDialError optionally specifies an alternate way to handle errors dialing Addr.
	// If nil, the error is logged and src is closed.
	// If non-nil, src is not closed automatically.
	OnDialError func(src net.Conn, dstDialErr error)
}

func goCloseConn(c net.Conn) { go c.Close() }

// HandleConn implements the Target interface.
func (dp *DialProxy) HandleConn(src net.Conn, auths map[string][]byte, asCluster map[string][]byte) {
	ctx := context.Background()
	var cancel context.CancelFunc
	if dp.DialTimeout >= 0 {
		ctx, cancel = context.WithTimeout(ctx, dp.dialTimeout())
	}
	dst, err := dp.dialContext()(ctx, "tcp", dp.Addr)
	if cancel != nil {
		cancel()
	}
	if err != nil {
		dp.onDialError()(src, err)
		return
	}
	defer goCloseConn(dst)
	defer goCloseConn(src)

	if ka := dp.keepAlivePeriod(); ka > 0 {
		if c, ok := src.(*net.TCPConn); ok {
			_ = c.SetKeepAlive(true)
			_ = c.SetKeepAlivePeriod(ka)
		}
		if c, ok := dst.(*net.TCPConn); ok {
			_ = c.SetKeepAlive(true)
			_ = c.SetKeepAlivePeriod(ka)
		}
	}

	errc := make(chan error, 1)
	go handleBackendRes(errc, src, dst, asCluster)
	go handleClientReq(errc, dst, src, auths)

	mu.Lock()
	if _, ok := socketAuthenticated[src.RemoteAddr().String()]; ok {
		delete(socketAuthenticated, src.RemoteAddr().String())
	}
	mu.Unlock()

	err = <-errc
	if err != nil {
		_ = src.Close()
		_ = dst.Close()
		log.Error().Msgf("%s", err)
		return
	}
}

// handleClientReq handle login/authenticate requests
// then proxy other datas to backend server
func handleClientReq(errc chan<- error, dst, src net.Conn, auths map[string][]byte) {
	buf := make([]byte, BufferSize)
	client := src.RemoteAddr().String()

	for {
		readN, readErr := src.Read(buf)

		if readN > 0 {
			b := buf[0:readN]
			mu.Lock()
			_, ok := socketAuthenticated[client]
			mu.Unlock()
			if ok {
				writeN, writeErr := dst.Write(b)
				if writeErr != nil {
					errc <- writeErr
					break
				}
				if readN != writeN {
					errc <- io.ErrShortWrite
					break
				}
			} else {
				if readN > 70 {
					// login command must have fields below
					// aerospike command is byte position 10
					if (b[0]&0xFF == 2) && (b[1]&0xFF == 2) && (b[10]&0xFF == 20) {
						// command byte = 20 is LOGIN
						// https://github.com/aerospike/aerospike-client-go/blob/master/admin_command.go#L43
						// response with session token, packet size is 90
						auth := bytes.SplitN(b[29:readN], []byte{0, 0, 0, 61, 3}, 2)
						if len(auth) == 2 {
							// validate login request
							errCode := authCheck(auths, auth)
							switch errCode {
							case 65:
								_, er := src.Write(invalidCredential)
								if er != nil {
									errc <- er
								}
								break
							case 60:
								_, er := src.Write(invalidUser)
								if er != nil {
									errc <- er
								}
								break
							default:
								buf := make([]byte, 90)
								// result code position 9, = 0 is OK
								buf[0] = 2
								buf[1] = 2
								buf[7] = 82
								buf[11] = 1
								buf[27] = 62
								//// session token header position 28, = 5 is session token
								buf[28] = 5
								buf[29] = 66
								// append hashed password
								copy(buf[30:], auth[1])

								// response to client a session token
								_, er := src.Write(buf)
								if er != nil {
									errc <- er
									break
								}
								mu.Lock()
								socketAuthenticated[client] = string(auth[0])
								mu.Unlock()
							}
						} else {
							_, er := src.Write(notAuth)
							if er != nil {
								errc <- er
							}
							break
						}
					} else if (b[0]&0xFF == 2) && (b[1]&0xFF == 2) && (b[10]&0xFF == 0) {
						// aerospike command is byte position 10
						// command byte = 0 is AUTHENTICATE
						// https://github.com/aerospike/aerospike-client-go/blob/master/admin_command.go#L30
						// Go Client: separate user and password with []byte{0, 0, 0, 61, 3}
						auth := bytes.SplitN(b[29:readN], []byte{0, 0, 0, 61, 3}, 2)
						if len(auth) != 2 {
							// Java Client: separate user and password with []byte{0, 0, 0, 62, 5, 66}
							auth = bytes.SplitN(b[29:readN], []byte{0, 0, 0, 62, 5, 66}, 2)
							if len(auth) != 2 {
								_, er := src.Write(notAuth)
								if er != nil {
									errc <- er
								}
								break
							}
						}
						// validate authenticate request
						errCode := authCheck(auths, auth)
						switch errCode {
						case 65:
							_, er := src.Write(invalidCredential)
							if er != nil {
								errc <- er
							}
							break
						case 60:
							_, er := src.Write(invalidUser)
							if er != nil {
								errc <- er
							}
							break
						default:
							// response with auth OK, packet size is 24
							// result code position 9, = 0 is OK
							buf := make([]byte, 24)
							buf[0] = 2
							buf[1] = 2
							buf[7] = 16

							_, er := src.Write(buf)
							if er != nil {
								errc <- er
								break
							}
							mu.Lock()
							socketAuthenticated[client] = string(auth[0])
							mu.Unlock()
						}
					} else {
						_, er := src.Write(notAuth)
						if er != nil {
							errc <- er
						}
						break
					}
				} else {
					_, er := src.Write(notAuth)
					if er != nil {
						errc <- er
					}
					break
				}
			}
		}

		if readErr == io.EOF {
			break
		}

		if readErr != nil {
			errc <- readErr
			break
		}
	}
}

// handleBackendRes handle backend server responses
// replace IP:PORT of aerospike server with proxy server
// then proxy other datas to backend server
func handleBackendRes(errc chan<- error, dst, src net.Conn, asCluster map[string][]byte) {
	buf := make([]byte, BufferSize)

	for {
		readN, readErr := src.Read(buf)
		b := buf[0:readN]

		if readN > 70 {
			// We can use bytes.Contains() but maybe slower
			// aerospike command: `peers-clear-std` or `service-clear-std`
			// replace `ip:port` of aerospike with `ip:port` of proxy server
			if (b[0]&0xFF == 2 && b[1]&0xFF == 1 && (b[7]&0xFF == 56 || b[7]&0xFF == 63)) || (b[0]&0xFF == 2 && b[1]&0xFF == 1 && b[7]&0xFF == 209 && b[8]&0xFF == 110 && b[9]&0xFF == 111 && b[10]&0xFF == 100 && b[11]&0xFF == 101) {
				for server, proxy := range asCluster {
					re, _ := regexp.Compile(server)
					if re.Match(b) {
						b = re.ReplaceAll(b, proxy)
						break
					}
				}
			}
			// send data to client
			_, writeErr := dst.Write(b)
			if writeErr != nil {
				errc <- writeErr
				break
			}
		} else {
			writeN, writeErr := dst.Write(b)
			if writeErr != nil {
				errc <- writeErr
				break
			}

			if readN != writeN {
				errc <- io.ErrShortWrite
				break
			}
		}

		if readErr == io.EOF {
			break
		}

		if readErr != nil {
			errc <- readErr
			break
		}
	}
}

func authCheck(users map[string][]byte, auth [][]byte) int {
	// validate login
	if pass, ok := users[string(auth[0])]; ok {
		// if password does't match
		if !bytes.Equal(pass, auth[1]) {
			// 65 is `invalid credential` response code
			return 65
		}
	} else {
		// 65 is `invalid credential` response code
		return 60
	}
	return 0
}

func (dp *DialProxy) keepAlivePeriod() time.Duration {
	if dp.KeepAlivePeriod != 0 {
		return dp.KeepAlivePeriod
	}
	return time.Minute
}

func (dp *DialProxy) dialTimeout() time.Duration {
	if dp.DialTimeout > 0 {
		return dp.DialTimeout
	}
	return 10 * time.Second
}

var defaultDialer = new(net.Dialer)

func (dp *DialProxy) dialContext() func(ctx context.Context, network, address string) (net.Conn, error) {
	if dp.DialContext != nil {
		return dp.DialContext
	}
	return defaultDialer.DialContext
}

func (dp *DialProxy) onDialError() func(src net.Conn, dstDialErr error) {
	if dp.OnDialError != nil {
		return dp.OnDialError
	}
	return func(src net.Conn, dstDialErr error) {
		log.Error().Msgf("proxy: for incoming conn %v, error dialing %q: %v", src.RemoteAddr().String(), dp.Addr, dstDialErr)
		src.Close()
	}
}
