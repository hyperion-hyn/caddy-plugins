package nat

import (
	"fmt"
	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
	gonat "github.com/fd/go-nat"
	"net"
	"strconv"
)

func init() {
	directive := "nat"
	caddy.RegisterPlugin(directive, caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
	httpserver.RegisterDevDirective(directive, "") //required
}

func setup(c *caddy.Controller) error {
	var (
		caddyPort    int64
		err          error
		nat          gonat.NAT
		deviceAddr   net.IP
		internalAddr net.IP
		externalAddr net.IP
	)

	if caddyPort, err = strconv.ParseInt(httpserver.Port, 10, 32); err != nil {
		return err
	}

	if nat, err = gonat.DiscoverGateway(); err != nil {
		return err
	}
	fmt.Printf("nat type: %s \n", nat.Type())

	if deviceAddr, err = nat.GetDeviceAddress(); err != nil {
		return err
	}
	fmt.Printf("device address: %s \n", deviceAddr)

	if internalAddr, err = nat.GetInternalAddress(); err != nil {
		return err
	}
	fmt.Printf("internal address: %s \n", internalAddr)

	if externalAddr, err = nat.GetExternalAddress(); err != nil {
		return err
	}
	fmt.Printf("external address: %s \n", externalAddr)

	if eport, err := nat.AddPortMapping("tcp", int(caddyPort), "http", 60); err != nil {
		return err
	} else {
		fmt.Printf("nat test-page: http://%s:%d/ \n", externalAddr, eport)
		c.OnShutdown(func() error {
			return nat.DeletePortMapping("tcp", int(caddyPort))
		})
	}
	return nil
}
