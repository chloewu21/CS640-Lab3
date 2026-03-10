package edu.wisc.cs.sdn.vnet.sw;

import net.floodlightcontroller.packet.Ethernet;
import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import java.util.*;

/**
 * @author Aaron Gember-Jacobson
 */
public class Switch extends Device
{	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Switch(String host, DumpFile logfile)
	{
		super(host,logfile);
	}

	private static class TableEntry {
		String iface;
		Long timeAdded;

		TableEntry(String iface) {
			this.iface = iface;
			this.timeAdded = System.currentTimeMillis();
		}
	}

	private Map<String, TableEntry> forwardingTable = new HashMap<>();
	private long TIMEOUT = 15000;

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
		
		/********************************************************************/
		String srcMac = etherPacket.getSourceMAC().toString();
		String dstMac = etherPacket.getDestinationMAC().toString();

		// Remove expired entries from forwarding table
		Iterator<Map.Entry<String, TableEntry>> iterator = forwardingTable.entrySet().iterator();
		while (iterator.hasNext()) {
			Map.Entry<String, TableEntry> entry = iterator.next();
			if (System.currentTimeMillis() - entry.getValue().timeAdded > TIMEOUT) {
				iterator.remove();
			}
		}
		
		// Add to fowarding table
		forwardingTable.put(srcMac, new TableEntry(inIface.getName()));

		// Forward the packet
		if (forwardingTable.containsKey(dstMac)) {
			sendPacket(etherPacket, interfaces.get(forwardingTable.get(dstMac).iface));
		} else { // send the packet out to all interfaces except the incoming one
			for (Iface iface : interfaces.values()) {
				if (!iface.getName().equals(inIface.getName())) {
					sendPacket(etherPacket, iface);
				}
			}
		}
			
	}
}
