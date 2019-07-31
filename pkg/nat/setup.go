package nat

import (
	"fmt"
	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
	gonat "github.com/fd/go-nat"
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
	caddyPort, err := strconv.ParseInt(httpserver.Port, 10, 32)
	if err != nil {
		fmt.Printf("error: %s \n", err)
	}

	nat, err := gonat.DiscoverGateway()
	if err != nil {
		fmt.Printf("error: %s \n", err)
	}
	fmt.Printf("nat type: %s \n", nat.Type())

	daddr, err := nat.GetDeviceAddress()
	if err != nil {
		fmt.Printf("error: %s \n", err)
	}
	fmt.Printf("device address: %s \n", daddr)

	iaddr, err := nat.GetInternalAddress()
	if err != nil {
		fmt.Printf("error: %s \n", err)
	}
	fmt.Printf("internal address: %s \n", iaddr)

	eaddr, err := nat.GetExternalAddress()
	if err != nil {
		fmt.Printf("error: %s \n", err)
	}
	fmt.Printf("external address: %s \n", eaddr)

	eport, err := nat.AddPortMapping("tcp", int(caddyPort), "http", 60)
	if err != nil {
		fmt.Printf("error: %s \n", err)
	}

	fmt.Printf("nat test-page: http://%s:%d/ \n", eaddr, eport)

	c.OnShutdown(func() error {
		return nat.DeletePortMapping("tcp", int(caddyPort))
	})
	return nil
}
