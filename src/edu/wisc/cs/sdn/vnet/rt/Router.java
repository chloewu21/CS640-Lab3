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
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;
	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
	}
	
	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }
	
	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
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
	
	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
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

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
				etherPacket.toString().replace("\n", "\n\t"));
		
		/********************************************************************/
		/* TODO: Handle packets                                             */

		// Check if frame contains IPv4 packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
			return;
		}
	
		// Verify checksum
		IPv4 payload = (IPv4) etherPacket.getPayload();
		short checksum = payload.getChecksum();
		payload.resetChecksum();
		payload.serialize();
		if (checksum != payload.getChecksum()) {
			return;
		}

		// Check for RIP packet
		if (payload.getProtocol() == IPv4.PROTOCOL_UDP) {
			UDP udp = (UDP) payload.getPayload();
			if (udp.getDestinationPort() == UDP.RIP_PORT) {
				handleRIPPacket(etherPacket, inIface);
				return;
			}
		}

		// Decrement TTL by 1
		byte ttl = payload.getTtl();
		ttl--;
		if (ttl == 0) {
			return; // drop if 0
		}
		payload.setTtl(ttl);

		// Check for IP match
		for (Iface iface : this.getInterfaces().values()) {
			if (payload.getDestinationAddress() == iface.getIpAddress()) {
				return; // drop if match
			}
		}

		// Find longest prefix match in routing table
		RouteEntry longestMatch = this.routeTable.lookup(payload.getDestinationAddress());
		System.out.println("Longest match: " + longestMatch);
		if (longestMatch == null) {
			return; // drop if no match
		}

		if (longestMatch.getInterface().getName().equals(inIface.getName())) {
			return; // drop if outgoing interface is same as incoming
		}


		// Set source MAC address
		System.out.println("Outgoing interface: " + longestMatch.getInterface().getName());
		Iface outIface = this.interfaces.get(longestMatch.getInterface().getName());
		System.out.println("Interfaces: " + this.getInterfaces());
		System.out.println("Outiface info:  " + IPv4.fromIPv4Address(this.getInterface(outIface.getName()).getIpAddress()));
		if (outIface == null) {
			System.out.println("Interface null");
			return;
		}
		if (this.getInterface(outIface.getName()).getMacAddress() == null) {
			System.out.println("MAC address null");
			return;
		}

		etherPacket.setSourceMACAddress(this.getInterface(outIface.getName()).getMacAddress().toBytes());

		// Set destination MAC address
		int nextHop = longestMatch.getGatewayAddress();
		if (nextHop == 0) {
			nextHop = payload.getDestinationAddress();
		}

		System.out.println("ARP " + IPv4.fromIPv4Address(nextHop));
		ArpEntry arpEntry = this.arpCache.lookup(nextHop);
		if (arpEntry == null) {
			System.out.println("No ARP entry for next hop");
			return; // drop if no ARP entry for next hop
		}	

		etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());

		// Recompute checksum and send
		payload.resetChecksum();
		payload.serialize();
		etherPacket.setPayload(payload);
		sendPacket(etherPacket, longestMatch.getInterface());

		/********************************************************************/
	}

	public void startRIP() {
		// Add direct neighbors to routing table
		for (Iface iface : this.getInterfaces().values()) {
			int subnet = iface.getIpAddress() & iface.getSubnetMask();
			this.routeTable.insert(subnet, 0, iface.getSubnetMask(), iface, 1);
			System.out.println("Added direct subnet: " + IPv4.fromIPv4Address(subnet) 
                           + "/" + IPv4.fromIPv4Address(iface.getSubnetMask()));
		}
		sendRIPRequestToAllNeighbors(); // send RIP request to every interface to ask neighbors to advertise routes
		// Start a thread to send RIP reponses every 10 seconds
		Thread RIPtimer = new Thread(() -> {
			while (true) {
				try {
					Thread.sleep(10000); // sleep for 10 seconds
					sendRIPResponseToAllNeighbors(); // send update to neighbors every 10 seconds
					removeStaleRoutes();
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
			}
		});
		RIPtimer.setDaemon(true);
		RIPtimer.start();
	}

	public void sendRIPRequestToAllNeighbors() {
		for (Iface iface : this.getInterfaces().values()) {
			sendRIPRequest(iface); // loop through all interfaces and send RIP request on each one
		}
	}

	public void sendRIPRequest(Iface outIface) {
		// Create RIPv2 request packet
		RIPv2 ripRequest = new RIPv2();
		ripRequest.setCommand(RIPv2.COMMAND_REQUEST);
		ripRequest.setEntries(new LinkedList<RIPv2Entry>()); // empty entries for request

		// Create UDP packet
		UDP udp = new UDP();
		udp.setSourcePort(UDP.RIP_PORT);
		udp.setDestinationPort(UDP.RIP_PORT);
		udp.setPayload(ripRequest);

		// Create IPv4 packet
		IPv4 ipv4 = new IPv4();
		ipv4.setSourceAddress(outIface.getIpAddress());
		ipv4.setDestinationAddress(IPv4.toIPv4Address("224.0.0.9")); // RIP multicast address
		ipv4.setTtl((byte) 1); 
		ipv4.setProtocol(IPv4.PROTOCOL_UDP);
		ipv4.setPayload(udp);

		// Create Ethernet frame
		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(outIface.getMacAddress().toBytes());
		ether.setDestinationMACAddress(Ethernet.toMACAddress("FF:FF:FF:FF:FF:FF")); // broadcast MAC address
		ether.setPayload(ipv4);

		// Send the packet
		sendPacket(ether, outIface);
		System.out.println("Sent RIP request on " + outIface.getName());

	}

	public void sendRIPResponseToAllNeighbors() {
		for (Iface iface : this.getInterfaces().values()) {
			sendRIPResponse(iface); // loop through all interfaces and send RIP response on each one
		}
	}

	public void sendRIPResponse(Iface outIface) {
		// Create RIPv2 response packet
		RIPv2 ripResponse = new RIPv2();
		ripResponse.setCommand(RIPv2.COMMAND_RESPONSE);

		LinkedList<RIPv2Entry> entries = new LinkedList<>();
		for (RouteEntry route : this.routeTable.getEntries()) {
			RIPv2Entry entry = new RIPv2Entry();
			entry.setAddress(route.getDestinationAddress());
			entry.setSubnetMask(route.getMaskAddress());
			entry.setNextHopAddress(route.getGatewayAddress());
			entry.setMetric(Math.min(route.getMetric(), 16));
			entries.add(entry);
		}
		ripResponse.setEntries(entries);

		// Create UDP packet
		UDP udp = new UDP();
		udp.setSourcePort(UDP.RIP_PORT);
		udp.setDestinationPort(UDP.RIP_PORT);
		udp.setPayload(ripResponse);

		// Create IPv4 packet
		IPv4 ipv4 = new IPv4();
		ipv4.setSourceAddress(outIface.getIpAddress());
		ipv4.setDestinationAddress(IPv4.toIPv4Address("224.0.0.9"));
		ipv4.setTtl((byte) 1);
		ipv4.setProtocol(IPv4.PROTOCOL_UDP);
		ipv4.setPayload(udp);

		// Create Ethernet frame
		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(outIface.getMacAddress().toBytes());
		ether.setDestinationMACAddress(Ethernet.toMACAddress("FF:FF:FF:FF:FF:FF"));
		ether.setPayload(ipv4);

		// Send the packet
		sendPacket(ether, outIface);
	}

	public void handleRIPPacket(Ethernet etherPacket, Iface inIface) {
		// Unwrap the packet to get the RIPv2 payload
		IPv4 ipv4 = (IPv4) etherPacket.getPayload();
		UDP udp = (UDP) ipv4.getPayload();
		RIPv2 rip = (RIPv2) udp.getPayload();

		// Check if packet is RIP request
		if (rip.getCommand() == RIPv2.COMMAND_REQUEST) {
			sendRIPResponse(inIface); // send response to requester
			return;
		}

		// If packet is RIP response, update routing table with new entries
		else if (rip.getCommand() == RIPv2.COMMAND_RESPONSE) {
			System.out.println("Received RIP response from " + IPv4.fromIPv4Address(ipv4.getSourceAddress()));
			for (RIPv2Entry entry : rip.getEntries()) {
				int newMetric = entry.getMetric() + 1; // add 1 to metric (number of hops) 
				if (newMetric > 16) {
					newMetric = 16; // cap at 16
				}
				int dest = entry.getAddress();
				int mask = entry.getSubnetMask();
				int gateway = inIface.getIpAddress();
				// int gateway = ipv4.getSourceAddress(); // set gateway to IP address of sender
				RouteEntry existingEntry = this.routeTable.find(dest, mask);
				if (existingEntry == null) {
					this.routeTable.insert(dest, gateway, mask, inIface, newMetric);
					System.out.println("Added new route to " + IPv4.fromIPv4Address(dest) + "/" + IPv4.fromIPv4Address(mask) +
                       " via " + IPv4.fromIPv4Address(gateway) + " metric " + newMetric);
				}
				else {
					if (newMetric < existingEntry.getMetric()) { // update if new metric is smaller
						existingEntry.setGatewayAddress(gateway);
						existingEntry.setInterface(inIface);
						existingEntry.setMetric(newMetric);
						System.out.println("Updated route to " + IPv4.fromIPv4Address(dest) + "/" + IPv4.fromIPv4Address(mask) +
                           " via " + IPv4.fromIPv4Address(gateway) + " metric " + newMetric);
					}
					existingEntry.setLastUpdate(); // refresh timer
				}
			}
		}
	}

	public void removeStaleRoutes() {
		long currentTime = System.currentTimeMillis();
		for (RouteEntry entry : this.routeTable.getEntries()) {
			if (entry.getGatewayAddress() == 0) { // skip direct routes
				continue;
			}

			if (currentTime - entry.getLastUpdate() > 30000) { // remove if last update was over 30 seconds ago
				this.routeTable.remove(entry.getDestinationAddress(), entry.getMaskAddress());
				System.out.println("Removed stale route: " + entry);
			}
		}
	}

}