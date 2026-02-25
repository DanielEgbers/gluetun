package firewall

import (
	"context"
	"fmt"

	"github.com/qdm12/gluetun/internal/netlink"
)

func (c *Config) SetEnabled(ctx context.Context, enabled bool) (err error) {
	c.stateMutex.Lock()
	defer c.stateMutex.Unlock()

	if enabled == c.enabled {
		if enabled {
			c.logger.Info("already enabled")
		} else {
			c.logger.Info("already disabled")
		}
		return nil
	}

	if !enabled {
		c.logger.Info("disabling...")
		if err = c.disable(ctx); err != nil {
			return fmt.Errorf("disabling firewall: %w", err)
		}
		c.enabled = false
		c.logger.Info("disabled successfully")
		return nil
	}

	c.logger.Info("enabling...")

	if err := c.enable(ctx); err != nil {
		return fmt.Errorf("enabling firewall: %w", err)
	}
	c.enabled = true
	c.logger.Info("enabled successfully")

	return nil
}

func (c *Config) disable(ctx context.Context) (err error) {
	if err = c.impl.ClearAllRules(ctx); err != nil {
		return fmt.Errorf("clearing all rules: %w", err)
	}
	if err = c.impl.SetIPv4AllPolicies(ctx, "ACCEPT"); err != nil {
		return fmt.Errorf("setting ipv4 policies: %w", err)
	}
	if err = c.impl.SetIPv6AllPolicies(ctx, "ACCEPT"); err != nil {
		return fmt.Errorf("setting ipv6 policies: %w", err)
	}

	const remove = true
	err = c.redirectPorts(ctx, remove)
	if err != nil {
		return fmt.Errorf("removing port redirections: %w", err)
	}

	return nil
}

// To use in defered call when enabling the firewall.
func (c *Config) fallbackToDisabled(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	if err := c.disable(ctx); err != nil {
		c.logger.Error("failed reversing firewall changes: " + err.Error())
	}
}

func (c *Config) enable(ctx context.Context) (err error) {
	if err = c.impl.SetIPv4AllPolicies(ctx, "DROP"); err != nil {
		return err
	}

	if err = c.impl.SetIPv6AllPolicies(ctx, "DROP"); err != nil {
		return err
	}

	defer func() {
		if err != nil {
			c.fallbackToDisabled(ctx)
		}
	}()

	const remove = false

	// Loopback traffic
	if err = c.impl.AcceptInputThroughInterface(ctx, "lo", remove); err != nil {
		return err
	}
	if err = c.impl.AcceptOutputThroughInterface(ctx, "lo", remove); err != nil {
		return err
	}

	if err = c.impl.AcceptEstablishedRelatedTraffic(ctx, remove); err != nil {
		return err
	}

	if err = c.allowVPNIP(ctx); err != nil {
		return err
	}

	localInterfaces := make(map[string]struct{}, len(c.localNetworks))
	for _, network := range c.localNetworks {
		err = c.impl.AcceptOutputFromIPToSubnet(ctx,
			network.InterfaceName, network.IP, network.IPNet, remove)
		if err != nil {
			return err
		}

		_, localInterfaceSeen := localInterfaces[network.InterfaceName]
		if localInterfaceSeen {
			continue
		}
		localInterfaces[network.InterfaceName] = struct{}{}
		err = c.impl.AcceptIpv6MulticastOutput(ctx, network.InterfaceName, remove)
		if err != nil {
			return fmt.Errorf("accepting IPv6 multicast output: %w", err)
		}
	}

	if err = c.allowOutboundSubnets(ctx); err != nil {
		return err
	}

	// Allows packets from any IP address to go through eth0 / local network
	// to reach Gluetun.
	for _, network := range c.localNetworks {
		if err := c.impl.AcceptInputToSubnet(ctx, network.InterfaceName, network.IPNet, remove); err != nil {
			return err
		}
	}

	if err = c.allowInputPorts(ctx); err != nil {
		return err
	}

	err = c.redirectPorts(ctx, remove)
	if err != nil {
		return fmt.Errorf("redirecting ports: %w", err)
	}

	if err := c.impl.RunUserPostRules(ctx, c.customRulesPath, remove); err != nil {
		return fmt.Errorf("running user defined post firewall rules: %w", err)
	}

	return nil
}

func (c *Config) allowVPNIP(ctx context.Context) (err error) {
	if !c.vpnConnection.IP.IsValid() {
		return nil
	}

	const remove = false
	interfacesSeen := make(map[string]struct{}, len(c.defaultRoutes))
	for _, defaultRoute := range c.defaultRoutes {
		_, seen := interfacesSeen[defaultRoute.NetInterface]
		if seen {
			continue
		}
		interfacesSeen[defaultRoute.NetInterface] = struct{}{}
		err = c.impl.AcceptOutputTrafficToVPN(ctx, defaultRoute.NetInterface, c.vpnConnection, remove)
		if err != nil {
			return fmt.Errorf("accepting output traffic through VPN: %w", err)
		}
	}

	return nil
}

func (c *Config) allowOutboundSubnets(ctx context.Context) (err error) {
	for _, subnet := range c.outboundSubnets {
		subnetIsIPv6 := subnet.Addr().Is6()
		firewallUpdated := false
		for _, defaultRoute := range c.defaultRoutes {
			defaultRouteIsIPv6 := defaultRoute.Family == netlink.FamilyV6
			ipFamilyMatch := subnetIsIPv6 == defaultRouteIsIPv6
			if !ipFamilyMatch {
				continue
			}
			firewallUpdated = true

			const remove = false
			err := c.impl.AcceptOutputFromIPToSubnet(ctx, defaultRoute.NetInterface,
				defaultRoute.AssignedIP, subnet, remove)
			if err != nil {
				return err
			}
		}

		if !firewallUpdated {
			c.logIgnoredSubnetFamily(subnet)
		}
	}
	return nil
}

func (c *Config) allowInputPorts(ctx context.Context) (err error) {
	for port, netInterfaces := range c.allowedInputPorts {
		for netInterface := range netInterfaces {
			const remove = false
			err = c.impl.AcceptInputToPort(ctx, netInterface, port, remove)
			if err != nil {
				return fmt.Errorf("accepting input port %d on interface %s: %w",
					port, netInterface, err)
			}
		}
	}
	return nil
}

func (c *Config) redirectPorts(ctx context.Context, remove bool) (err error) {
	for _, portRedirection := range c.portRedirections {
		err = c.impl.RedirectPort(ctx, portRedirection.interfaceName, portRedirection.sourcePort,
			portRedirection.destinationPort, remove)
		if err != nil {
			return err
		}
	}
	return nil
}
