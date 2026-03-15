package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;

import java.util.LinkedList;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{
    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    /** RIP multicast address 224.0.0.9 */
    private static final String RIP_MULTICAST_IP   = "224.0.0.9";
    /** Ethernet broadcast used for RIP requests / unsolicited responses */
    private static final String BROADCAST_MAC      = "FF:FF:FF:FF:FF:FF";
    /** Metric infinity – routes at or above this are unreachable */
    private static final int    RIP_INFINITY        = 16;
    /** A route is stale if no update was received for 30 s */
    private static final long   ROUTE_TIMEOUT_MS    = 30_000L;
    /** Unsolicited response / stale-route-check interval */
    private static final long   RIP_UPDATE_INTERVAL = 10_000L;

    // -----------------------------------------------------------------------
    // State
    // -----------------------------------------------------------------------

    /** Routing table for the router */
    private RouteTable routeTable;

    /** ARP cache for the router */
    private ArpCache arpCache;

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    public Router(String host, DumpFile logfile)
    {
        super(host, logfile);
        this.routeTable = new RouteTable();
        this.arpCache   = new ArpCache();
    }

    public RouteTable getRouteTable()
    { return this.routeTable; }

    // -----------------------------------------------------------------------
    // Static table / ARP cache loading
    // -----------------------------------------------------------------------

    public void loadRouteTable(String routeTableFile)
    {
        if (!routeTable.load(routeTableFile, this))
        {
            System.err.println("Error setting up routing table from file "
                    + routeTableFile);
            System.exit(1);
        }
        System.out.println("Loaded static route table");
        System.out.println("-------------------------------------------------");
        System.out.print(this.routeTable.toString());
        System.out.println("-------------------------------------------------");
    }

    public void loadArpCache(String arpCacheFile)
    {
        if (!arpCache.load(arpCacheFile))
        {
            System.err.println("Error setting up ARP cache from file "
                    + arpCacheFile);
            System.exit(1);
        }
        System.out.println("Loaded static ARP cache");
        System.out.println("----------------------------------");
        System.out.print(this.arpCache.toString());
        System.out.println("----------------------------------");
    }

    // -----------------------------------------------------------------------
    // Main packet handler
    // -----------------------------------------------------------------------

    @Override
    public void handlePacket(Ethernet etherPacket, Iface inIface)
    {
        System.out.println("*** -> Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));

        // Only handle IPv4 frames
        if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
        { return; }

        IPv4 ipPacket = (IPv4) etherPacket.getPayload();

        // Verify IP checksum
        short savedChecksum = ipPacket.getChecksum();
        ipPacket.resetChecksum();
        ipPacket.serialize();           // recomputes checksum in place
        if (savedChecksum != ipPacket.getChecksum())
        {
            System.out.println("Bad IP checksum – dropping");
            return;
        }

        // Intercept RIP packets (UDP dst port 520) before normal forwarding
        if (ipPacket.getProtocol() == IPv4.PROTOCOL_UDP)
        {
            UDP udp = (UDP) ipPacket.getPayload();
            if (udp.getDestinationPort() == UDP.RIP_PORT)
            {
                handleRIPPacket(etherPacket, inIface);
                return;
            }
        }

        // ---- Normal IP forwarding ----

        // Decrement TTL; drop if it hits zero
        byte ttl = ipPacket.getTtl();
        if (--ttl == 0)
        { return; }
        ipPacket.setTtl(ttl);

        // Drop packets destined for one of our own interfaces
        for (Iface iface : this.getInterfaces().values())
        {
            if (ipPacket.getDestinationAddress() == iface.getIpAddress())
            { return; }
        }

        // Longest-prefix match
        RouteEntry match = this.routeTable.lookup(ipPacket.getDestinationAddress());
        if (match == null)
        {
            System.out.println("No route – dropping");
            return;
        }

        // Do not forward back out the same interface the packet arrived on
        if (match.getInterface().getName().equals(inIface.getName()))
        { return; }

        Iface outIface = this.getInterface(match.getInterface().getName());
        if (outIface == null)
        { return; }

        // Determine next-hop IP (gateway if set, otherwise destination)
        int nextHop = match.getGatewayAddress();
        if (nextHop == 0)
        { nextHop = ipPacket.getDestinationAddress(); }

        ArpEntry arpEntry = this.arpCache.lookup(nextHop);
        if (arpEntry == null)
        {
            System.out.println("No ARP entry for " +
                    IPv4.fromIPv4Address(nextHop) + " – dropping");
            return;
        }

        // Rewrite Ethernet header and send
        etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());
        etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());

        // Recompute IP checksum after TTL change
        ipPacket.resetChecksum();
        ipPacket.serialize();
        etherPacket.setPayload(ipPacket);

        sendPacket(etherPacket, outIface);
    }

    // -----------------------------------------------------------------------
    // RIP initialisation
    // -----------------------------------------------------------------------

    /**
     * Called from Main when no static route table is provided.
     * Seeds the table with directly-connected subnets, broadcasts a
     * RIP request to all neighbours, then starts a periodic update thread.
     */
    public void startRIP()
    {
        // Add one entry per directly-connected subnet (gateway = 0, metric = 1)
        for (Iface iface : this.getInterfaces().values())
        {
            int subnet = iface.getIpAddress() & iface.getSubnetMask();
            this.routeTable.insert(subnet, 0, iface.getSubnetMask(), iface, 1);
            System.out.println("Direct subnet: "
                    + IPv4.fromIPv4Address(subnet)
                    + "/" + IPv4.fromIPv4Address(iface.getSubnetMask()));
        }

        // Solicit routes from every neighbour
        sendRIPRequestToAllInterfaces();

        // Periodic thread: send unsolicited responses and purge stale entries
        Thread timer = new Thread(() ->
        {
            while (true)
            {
                try
                {
                    Thread.sleep(RIP_UPDATE_INTERVAL);
                    sendRIPResponseToAllInterfaces();
                    removeStaleRoutes();
                }
                catch (InterruptedException e)
                { Thread.currentThread().interrupt(); break; }
            }
        });
        timer.setDaemon(true);
        timer.start();
    }

    // -----------------------------------------------------------------------
    // Sending RIP packets
    // -----------------------------------------------------------------------

    /** Broadcast a RIP request out every interface. */
    private void sendRIPRequestToAllInterfaces()
    {
        for (Iface iface : this.getInterfaces().values())
        { sendRIPRequest(iface); }
    }

    /**
     * Build and send a RIP REQUEST out {@code outIface}.
     * Destination: multicast 224.0.0.9 / broadcast MAC.
     */
    private void sendRIPRequest(Iface outIface)
    {
        RIPv2 rip = new RIPv2();
        rip.setCommand(RIPv2.COMMAND_REQUEST);
        rip.setEntries(new LinkedList<RIPv2Entry>());

        Ethernet ether = buildRIPEthernet(rip, outIface,
                IPv4.toIPv4Address(RIP_MULTICAST_IP),
                Ethernet.toMACAddress(BROADCAST_MAC));

        System.out.println("Sending RIP REQUEST on " + outIface.getName());
        sendPacket(ether, outIface);
    }

    /** Broadcast an unsolicited RIP response out every interface. */
    private void sendRIPResponseToAllInterfaces()
    {
        for (Iface iface : this.getInterfaces().values())
        { sendRIPResponseMulticast(iface); }
    }

    /**
     * Build and send an unsolicited (multicast) RIP RESPONSE out
     * {@code outIface} advertising all known routes.
     */
    private void sendRIPResponseMulticast(Iface outIface)
    {
        Ethernet ether = buildRIPEthernet(
                buildRIPResponse(),
                outIface,
                IPv4.toIPv4Address(RIP_MULTICAST_IP),
                Ethernet.toMACAddress(BROADCAST_MAC));

        sendPacket(ether, outIface);
    }

    /**
     * Build and send a unicast RIP RESPONSE back to the router that sent us
     * a request.  The destination IP and MAC come from the received packet.
     */
    private void sendRIPResponseUnicast(Iface outIface,
                                        int   dstIp,
                                        byte[] dstMac)
    {
        Ethernet ether = buildRIPEthernet(
                buildRIPResponse(),
                outIface,
                dstIp,
                dstMac);

        sendPacket(ether, outIface);
    }

    // -----------------------------------------------------------------------
    // RIP packet handler
    // -----------------------------------------------------------------------

    /**
     * Dispatches an arriving RIP packet (already confirmed to be UDP/520).
     */
    public void handleRIPPacket(Ethernet etherPacket, Iface inIface)
    {
        IPv4   ipv4 = (IPv4)   etherPacket.getPayload();
        UDP    udp  = (UDP)    ipv4.getPayload();
        RIPv2  rip  = (RIPv2)  udp.getPayload();

        if (rip.getCommand() == RIPv2.COMMAND_REQUEST)
        {
            // Reply directly to the sender (unicast), not the whole subnet
            sendRIPResponseUnicast(
                    inIface,
                    ipv4.getSourceAddress(),
                    etherPacket.getSourceMACAddress());
        }
        else if (rip.getCommand() == RIPv2.COMMAND_RESPONSE)
        {
            processRIPResponse(rip, ipv4.getSourceAddress(), inIface);
        }
    }

    /**
     * Apply Bellman-Ford update: for each entry in the received RIP response,
     * update the local routing table if the advertised path is better.
     *
     * @param rip      the received RIPv2 response
     * @param senderIp IP address of the router that sent the response
     *                 (used as the gateway for any new/updated routes)
     * @param inIface  interface on which the response arrived
     */
    private void processRIPResponse(RIPv2 rip, int senderIp, Iface inIface)
    {
        for (RIPv2Entry entry : rip.getEntries())
        {
            int newMetric = entry.getMetric() + 1;
            if (newMetric >= RIP_INFINITY)
            { newMetric = RIP_INFINITY; }

            int dest    = entry.getAddress();
            int mask    = entry.getSubnetMask();
            int gateway = senderIp;

            RouteEntry existing = this.routeTable.find(dest, mask);

            if (existing == null)
            {
                // Only add reachable routes
                if (newMetric < RIP_INFINITY)
                {
                    this.routeTable.insert(dest, gateway, mask, inIface, newMetric);
                    System.out.println("RIP: added route "
                            + IPv4.fromIPv4Address(dest)
                            + " metric=" + newMetric);
                }
            }
            else
            {
                // Never evict a directly-connected subnet entry
                if (existing.getGatewayAddress() == 0)
                { continue; }

                if (newMetric < existing.getMetric())
                {
                    // Strictly better path – update
                    existing.setGatewayAddress(gateway);
                    existing.setInterface(inIface);
                    existing.setMetric(newMetric);
                    existing.setLastUpdate();
                    System.out.println("RIP: updated route "
                            + IPv4.fromIPv4Address(dest)
                            + " metric=" + newMetric);
                }
                else if (inIface.getName().equals(existing.getInterface().getName())
                         && gateway == existing.getGatewayAddress())
                {
                    // Same next-hop refreshing its own advertisement
                    existing.setMetric(newMetric);
                    existing.setLastUpdate();

                    // If the neighbour is now advertising infinity, remove the route
                    if (newMetric >= RIP_INFINITY)
                    {
                        this.routeTable.remove(dest, mask);
                        System.out.println("RIP: removed unreachable route "
                                + IPv4.fromIPv4Address(dest));
                    }
                }
                else
                {
                    // Same or worse metric from a different next-hop – just refresh timer
                    existing.setLastUpdate();
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Stale-route expiry
    // -----------------------------------------------------------------------

    /**
     * Remove any dynamically-learned route that has not been refreshed
     * within {@value #ROUTE_TIMEOUT_MS} ms.
     * Direct (gateway == 0) entries are never removed.
     */
    private void removeStaleRoutes()
    {
        long now = System.currentTimeMillis();
        for (RouteEntry entry : this.routeTable.getEntries())
        {
            if (entry.getGatewayAddress() == 0)
            { continue; }   // keep directly-connected subnets forever

            if (now - entry.getLastUpdate() > ROUTE_TIMEOUT_MS)
            {
                this.routeTable.remove(
                        entry.getDestinationAddress(),
                        entry.getMaskAddress());
                System.out.println("RIP: timed out route "
                        + IPv4.fromIPv4Address(entry.getDestinationAddress()));
            }
        }
    }

    // -----------------------------------------------------------------------
    // Packet-building helpers
    // -----------------------------------------------------------------------

    /**
     * Build a RIPv2 RESPONSE packet containing every route in the table.
     */
    private RIPv2 buildRIPResponse()
    {
        RIPv2 rip = new RIPv2();
        rip.setCommand(RIPv2.COMMAND_RESPONSE);

        LinkedList<RIPv2Entry> entries = new LinkedList<>();
        for (RouteEntry route : this.routeTable.getEntries())
        {
            RIPv2Entry e = new RIPv2Entry();
            e.setAddressFamily(RIPv2Entry.ADDRESS_FAMILY_IPv4);
            e.setAddress(route.getDestinationAddress());
            e.setSubnetMask(route.getMaskAddress());
            e.setNextHopAddress(route.getGatewayAddress());
            e.setMetric(Math.min(route.getMetric(), RIP_INFINITY));
            entries.add(e);
        }
        rip.setEntries(entries);
        return rip;
    }

    /**
     * Wrap a RIPv2 payload in UDP / IPv4 / Ethernet headers ready to send.
     *
     * @param rip      the RIPv2 payload
     * @param outIface interface the packet will leave on (provides src IP & MAC)
     * @param dstIp    destination IPv4 address (multicast or unicast)
     * @param dstMac   destination MAC address  (broadcast or unicast)
     */
    private Ethernet buildRIPEthernet(RIPv2  rip,
                                      Iface  outIface,
                                      int    dstIp,
                                      byte[] dstMac)
    {
        UDP udp = new UDP();
        udp.setSourcePort(UDP.RIP_PORT);
        udp.setDestinationPort(UDP.RIP_PORT);
        udp.setPayload(rip);

        IPv4 ipv4 = new IPv4();
        ipv4.setSourceAddress(outIface.getIpAddress());
        ipv4.setDestinationAddress(dstIp);
        ipv4.setTtl((byte) 1);
        ipv4.setProtocol(IPv4.PROTOCOL_UDP);
        ipv4.setPayload(udp);

        Ethernet ether = new Ethernet();
        ether.setEtherType(Ethernet.TYPE_IPv4);
        ether.setSourceMACAddress(outIface.getMacAddress().toBytes());
        ether.setDestinationMACAddress(dstMac);
        ether.setPayload(ipv4);

        return ether;
    }
}
