//package a2;

import java.io.*;
import java.net.InetAddress;
import java.util.Vector;

import javax.xml.bind.DatatypeConverter;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Arp.OpCode;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

public class ids {
	//retrieved from http://stackoverflow.com/questions/2241229/going-from-127-0-0-1-to-2130706433-and-back-again
	//used to convert an ip address to a long integer 
	public static long ip2long(InetAddress ip){
		byte[] bytes = ip.getAddress();
        long temp = 0;
        for (byte val : bytes) {
        	temp <<= 8;
        	temp |= val & 0xff;
        }
        return temp;
	}
	public static void main(String[] args) throws FileNotFoundException, IOException {
		
		System.loadLibrary("jnetpcap");
		
		//pcap file path
		String filePath = args[0];
		//String filePath = "D:/U_WATERLOO/Fall 2015/CS 458/support-files/skeletons/java/a2/src/a2/q1-anomaly.pcap";
		//String filePath = "D:/U_WATERLOO/Fall 2015/CS 458/support-files/skeletons/java/a2/src/a2/q2-spoofed.pcap";
		//String filePath = "D:/U_WATERLOO/Fall 2015/CS 458/support-files/skeletons/java/a2/src/a2/q3-servers.pcap";
		//String filePath = "D:/U_WATERLOO/Fall 2015/CS 458/support-files/skeletons/java/a2/src/a2/q4-sinkholes.pcap";
		//String filePath = "D:/U_WATERLOO/Fall 2015/CS 458/support-files/skeletons/java/a2/src/a2/q5-arp.pcap";
		//String filePath = "D:/U_WATERLOO/Fall 2015/CS 458/support-files/skeletons/java/a2/src/a2/q6-unicode.pcap";
		//String filePath = "D:/U_WATERLOO/Fall 2015/CS 458/support-files/skeletons/java/a2/src/a2/q7-ntp.pcap";
		
		//error buffer
		StringBuilder errbuf = new StringBuilder();
		
		//load in list of sinkholes
		//String sinkhole = "sinkholes.txt";
		//String sinkhole = "D:/U_WATERLOO/Fall 2015/CS 458/support-files/skeletons/java/a2/src/a2/sinkholes.txt"
		Vector<String> sinkholeip = new Vector<String>(); 
		int i = 0;
	    String line = "";
			// FileReader reads text files
		FileReader fileReader = new FileReader("sinkholes.txt");
		//wrap FileReader in BufferedReader.
		BufferedReader bufferedReader = new BufferedReader(fileReader);
		try {
            while((line = bufferedReader.readLine()) != null) {
            	sinkholeip.addElement(line);
            }
            //close files.
            bufferedReader.close();         
        }
        catch(FileNotFoundException ex) {
            System.out.println("Unable to open file");                
        }
        catch(IOException ex) {
            System.out.println("Error reading file");
        }
		
		//try to open the pcap file
		Pcap pcap = Pcap.openOffline(filePath, errbuf); 
		if(pcap == null){
			System.err.println(errbuf);
			return;
		}
		
		Ip4 ip = new Ip4();
		Tcp tcp = new Tcp();
		Http http = new Http();
		Udp udp = new Udp();
		Arp arp = new Arp();
		Ethernet eth = new Ethernet();
        PcapHeader hdr = new PcapHeader(JMemory.POINTER);  
        JBuffer buf = new JBuffer(JMemory.POINTER);
        
		int id = JRegistry.mapDLTToId(pcap.datalink()); 
		int totalSize = 0;
		int totalPackets = 0;
		long min = ip2long(InetAddress.getByName("10.0.0.0"));
		long max = ip2long(InetAddress.getByName("10.255.255.255"));
		   
        byte[] src = new byte[4];
        byte[] dst = new byte[4];
		long srcLong = 0;
		long dstLong = 0;
		String source = "";
		String destination = "";
		
    	Vector<String> ipAddr = new Vector<String>();
    	Vector<String> macAddr = new Vector<String>();
		
		while (pcap.nextEx(hdr, buf) == Pcap.NEXT_EX_OK) {  
			  
            //copy in the packet
            PcapPacket packet = new PcapPacket(hdr, buf);  
            
            //anomaly check
            //increment packet counter
            totalPackets++;
            //count size of each packet
            totalSize += packet.size();
            
            //map headers
            packet.scan(id);
            
            if(packet.hasHeader(ip)){
                //get source ip addr
                src = packet.getHeader(ip).source();
                source = FormatUtils.ip(src);
                srcLong = ip2long(InetAddress.getByName(source));
                //get destination ip addr
                dst = packet.getHeader(ip).destination();
                destination =  FormatUtils.ip(dst); 
                dstLong = ip2long(InetAddress.getByName(destination));
                
//                check for spoofing
//                safe packets
//                	src in range, dst not in range
//                	src not in range, dst in range
//                	src in range, dst in range
//                dangous packets
//                	src not in range and dst not in range
                
	            if(!(srcLong >= min && srcLong <= max) && !(dstLong >= min && dstLong <= max)){
	            	//System.out.println(srcLong+" "+ dstLong +" "+ min +" "+max);
		            System.out.println("[Spoofed IP address]: src:"+source+", dst:"+destination);
	            }
	            //check for unauthorized servers
	            //connection attempt: src addr not in bound, dest in bound, syn flag up, ack flag down
	            if(packet.hasHeader(tcp)){
		            if(!(srcLong >= min && srcLong <= max) && (dstLong >= min && dstLong <= max) 
		            		&& packet.getHeader(tcp).flags_SYN() && !packet.getHeader(tcp).flags_ACK()){
		            	System.out.println("[Attempted server connection]: rem:" + source + ", srv:" + destination +
		            			", port: " + packet.getHeader(tcp).destination());
		            }
		            //accept connection: src in bound, dst out of bound, syn + ack flag up
		            else if((srcLong >= min && srcLong <= max) && !(dstLong >= min && dstLong <= max) 
		            		&& packet.getHeader(tcp).flags_SYN() && packet.getHeader(tcp).flags_ACK()){
		            	System.out.println("[Accepted server connection]: rem:" + destination + ", srv:" + source +
		            			", port: " + packet.getHeader(tcp).source());
		            }
	            }
	            //worms
	            if(packet.hasHeader(tcp) && packet.hasHeader(http)){
	            	//worm requests
	            	byte[] data = http.getByteArray(0, http.size());	            	
	            	StringBuilder sb = new StringBuilder();
            		for (byte b : data) {
            			sb.append(String.format("%02X", b));
            		}
            		byte[] b = DatatypeConverter.parseHexBinary(sb.toString());
        			String temp = new String(b, "UTF-8");
        			//parse the worms, break as soon as we see a unicode exploit
            		for(i = 0; i < temp.length(); i++){
            			if(temp.substring(i,i+1).matches("%")){
            				if(temp.substring(i+1,i+2).matches("[a-fA-F0-9]") && temp.substring(i+2,i+3).matches("[a-fA-F0-9]")){
            					System.out.println("[Unicode IIS exploit]: src:" + source + ", dst:" + destination);
            					break;
            				}
            				else if(temp.substring(i+1,i+2).matches("[Cc]") && temp.substring(i+2,i+3).matches("[01]")){
            					System.out.println("[Unicode IIS exploit]: src:" + source + ", dst:" + destination);
            					break;
            				}
            			}
            		}

	            }
            }            
            //sinkhole lookup and ntp
            //can only deal with the response as those are the only packets with ip fields
            if(packet.hasHeader(udp)){
                //get source ip addr
                src = packet.getHeader(ip).source();
                source = FormatUtils.ip(src);
                srcLong = ip2long(InetAddress.getByName(source));
                //get destination ip addr
                dst = packet.getHeader(ip).destination();
                destination =  FormatUtils.ip(dst); 
                dstLong = ip2long(InetAddress.getByName(destination));
                /*System.out.println("udp: "+ source +", "+ destination);
                
                System.out.println("eth size: "+ packet.getHeader(eth).size());
                System.out.println("ip size: "+ packet.getHeader(ip).size());
                System.out.println("udp size: "+ packet.getHeader(udp).size());
                System.out.println("packet size: "+ packet.size());*/
                
                /*byte[] data1 = packet.getByteArray(0, packet.size());
        		StringBuilder sb1 = new StringBuilder();
        		for (byte b : data1) {
        			sb1.append(String.format("%02X ", b));
        		}
                System.out.println(sb1);*/
            	
            	//ddos
            	if(packet.getHeader(udp).destination() == 123){
                    //System.out.println("ntp");
                	byte[] data = packet.getByteArray(0, packet.size());
            		StringBuilder sb = new StringBuilder();
            		for (byte b : data) {
            			sb.append(String.format("%02X", b));
            		}
            		//access the ntp layer and find hh=2a
            		String ddos = sb.toString().substring(
            				2*(packet.getHeader(eth).size()+packet.getHeader(ip).size()+packet.getHeader(udp).size()), 
            				2*packet.size());
            		for(i = 0; i+2 < ddos.length(); i++){
            			if(ddos.substring(i, i+2).equals("2A")){
            				System.out.println("[NTP DDoS]: vic:"+source+", srv:"+destination);        				
            			}
            		}
                }
            	//System.out.println(packet.hasHeader(payload));
            	else{//if(newPacket.hasHeader(payload)){
            		//get the payload to show up as hex 
                    //System.out.println("sinkhole");
                    int ethSize = packet.getHeader(eth).size();
                    int ipSize = packet.getHeader(ip).size();
                    int udpSize = packet.getHeader(udp).size();
                    int payloadStart = 2*(ethSize + ipSize + udpSize);
            		byte[] data = packet.getByteArray(0, packet.size());
            		StringBuilder sb = new StringBuilder();
            		for (byte b : data) {
            			sb.append(String.format("%02X", b));
            		}
            		String query = sb.toString().substring(payloadStart, sb.toString().length());
            		String flag = ""+query.charAt(4)+query.charAt(5)+
            				query.charAt(6)+query.charAt(7);
            		
            		//find how many answers there are for the query
            		String answers = query.substring(12, 16);
            		//System.out.println(answers);
            		//System.out.println(flag);
            		//only looking for packets with query responses(aka anything between 0x8000 and 0xFFF0)
            		if(flag.compareTo("8000")>0 && !(flag.compareTo("FFF0")>0)){
            			//System.out.println("ha");
            			//find the host name
            			String host = "";
            			String temp = "";
            			String classIn = "";
            			boolean type_a = false;
            			int locationCounter = 24;
            			//host name begin at byte 24, and continues until we see the type
            			while(locationCounter+8 < query.length()){
            				temp = ""+query.charAt(locationCounter)+query.charAt(locationCounter+1)+
            						query.charAt(locationCounter+2)+query.charAt(locationCounter+3);
            				classIn = ""+query.charAt(locationCounter+4)+query.charAt(locationCounter+5)+
            						query.charAt(locationCounter+6)+query.charAt(locationCounter+7);
            				//only do stuff if type is type a (0001)
            				if(temp.equals("0001") && classIn.equals("0001")){
            					locationCounter += 8;
            					type_a = true; 
            					break;
            				}
            				//all other type requests get rejected
            				else if((temp.equals("0005") || temp.equals("0002") || temp.equals("000F")) && classIn.equals("0001")) break;
            				host += temp;
            				locationCounter+=4;
            			}
            			//System.out.println(type_a);
            			if(type_a){
	            			//host name now in hex, need to turn it into string
	            			byte[] b = DatatypeConverter.parseHexBinary(host);
	            			host = new String(b, "UTF-8");
	            			//System.out.println(host);
	            			//regrex check for the finishing touches
	            			temp = "";
	            			boolean pre = false;
	            			for(i = 0; i+2 < host.length(); i++){
	            				//first char of the domain name
	            				if((!pre && host.substring(i, i+1).matches("[a-zA-Z0-9]"))
	            						||(pre && host.substring(i, i+1).matches("[a-zA-Z0-9]") 
	            								&& !(host.substring(i+1, i+2).matches("[a-zA-Z0-9]")))){
	            					temp += host.substring(i, i+1);
	            					pre = true;
	            				}
	            				//all chars but the first and last one 
	            				else if(host.substring(i, i+1).matches("[a-zA-Z0-9-]")){
	            					temp += host.substring(i, i+1);
	            					pre = true;
	            				}
	            				//inserting the period
	            				else if (pre && i+1 < host.length()){
	            					temp += ".";
	            					pre = false;
	            				}
	            			}
	            			//check last char
	            			if(host.substring(i, i+1).matches("[a-zA-Z0-9]")) temp += host.substring(i, i+1);
	            			host = temp;
	            			
	            			//System.out.println(host);
	            			
	            			//run the following checks for each type a dns answer that shows up
	            			//ip garenteed to be at the last 8 bytes of the answer
            				//locationCounter points to the start of the first answer
            				//answer format
            				//name: 4 hex
            				//type: 4 hex
            				//class: 4 hex
            				//ttl: 8 hex
            				//data length: 4 hex
            				//rest: 2*value of data length
	            			//System.out.println(query);
	            			for(long j=0; j<Long.parseLong(answers, 16); j++){
	            				int answerCounter = locationCounter + 4 + 4 + 4 + 8 + 4;
	            				while(answerCounter < query.length()){
		            				if(query.substring(locationCounter+4, locationCounter+8).equals("0001")
		            						&& query.substring(locationCounter+8, locationCounter+12).equals("0001")){
		            					String ipDNS = "";
			                			for(int k = answerCounter; k < answerCounter+8; k++){
			                				ipDNS += query.charAt(k);
			                			}
			                			//System.out.println(ipDNS+", "+ipDNS.length()+", "+ j);
			                			ipDNS = InetAddress.getByAddress(DatatypeConverter.parseHexBinary(ipDNS)).getHostAddress();
				            			//check with the known list
				            			for(i=0; i<sinkholeip.size(); i++){
				                			//find ip address from answers
				            				//sinkhole found
				            				if(ipDNS.equals(sinkholeip.elementAt(i))){
					            				System.out.println("[Sinkhole lookup]: src:" + destination + 
					            						", host:" + host + ", ip:" + ipDNS);
						            			break;
				            				}
				            			}
				            			answerCounter += 8; 
		            				}
		            				else{            					
		            					answerCounter += Long.parseLong(query.substring(answerCounter-4, answerCounter), 16);
		            				}
	            				}
	            			}
            			}
            		}
            	}
            }
            //arp spoofing
            if(packet.hasHeader(arp)){
            	//get the ip, the mac addr and the op code
            	String srcMac = FormatUtils.mac(packet.getHeader(arp).sha());
            	String srcIp = FormatUtils.ip(packet.getHeader(arp).spa());
            	OpCode opCode = packet.getHeader(arp).operationEnum();
            	
            	if(opCode == OpCode.valueOf("REPLY")){
	            	for(i = 0; i < ipAddr.size(); i++){
	            		//System.err.println("ha");
	            		//System.out.println(ipAddr.elementAt(i).equals(srcIp)+" "+macAddr.elementAt(i).equals(srcMac));
	            		if(ipAddr.elementAt(i).equals(srcIp)){
	            			if(!macAddr.elementAt(i).equals(srcMac)){
	            				System.out.println("[Potential ARP spoofing]: ip:" + srcIp +
	            						", old:" + macAddr.elementAt(i) + ", new:" + srcMac);
	            				ipAddr.removeElementAt(i);
	            				macAddr.removeElementAt(i);
	            			}
	            		}
	            	}
	            	ipAddr.add(srcIp);
	            	macAddr.add(srcMac);
            	}
            }
        }  
		
		pcap.close();
		
		System.out.println("Analyzed "+ totalPackets +" packets, "+ totalSize +" bytes");
	}
}
