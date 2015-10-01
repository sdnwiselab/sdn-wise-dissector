-- SDN-WISE Protocol Dissector
-- Authors: M. Fede - Y. Trapani

sdn_wise_proto = Proto("sdn-wise","SDN-WISE Protocol")
len = ProtoField.uint8("sdn-wise.len","Lenght",base.DEC)
id = ProtoField.uint8("sdn-wise.id","NetworkId",base.DEC)
src = ProtoField.uint16("sdn-wise.src","Source Address",base.DEC)
dst = ProtoField.uint16("sdn-wise.dst","Destination Address",base.DEC)
typ = ProtoField.uint8("sdn-wise.typ","Type",base.DEC)
ttl = ProtoField.uint8("sdn-wise.ttl","Time To Live",base.DEC)
nxhop = ProtoField.uint16("sdn-wise.nxhop","Next Hop Address",base.DEC)

sdn_wise_proto.fields = {len,id,src,dst,typ,ttl,nxhop}

-- Dissector
function sdn_wise_proto.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "SDN-WISE"
    local subtree = tree:add(sdn_wise_proto,buffer(),"SDN-WISE Protocol Data")
	subtree:add_le(len,buffer(0,1))
	subtree:add_le(id,buffer(1,1))
	subtree:add_le(src,buffer(2,2))
	subtree:add_le(dst,buffer(4,2))
	subtree:add_le(typ,buffer(6,1))
	subtree:add_le(ttl,buffer(7,1))
	subtree:add_le(nxhop,buffer(8,2))
	local typ = buffer(6,1): le_uint() 
    
--DATA
	if typ == 0 then
		subtree:add(buffer(10,1), "Payload: " .. buffer:len()-10)
	end

--BEACON
	if typ == 1 then 
		subtree:add(buffer(10,1), "Dist. hop: " .. buffer(10,1):uint())
		subtree:add(buffer(11,1), "Batt: " .. buffer(11,1):uint())
	end

--REPORT
	if typ ==2 then 
		subtree:add(buffer(10,1), "Dist. hop: " .. buffer(10,1):uint())
		subtree:add(buffer(11,1), "Battery: " .. buffer(11,1):uint())
     	subtree:add(buffer(12,1), "Neighbours: " .. buffer(12,1):uint()) 
	
		j = buffer(12,1):uint()
		local n = 13
		for i =1,j do
			subtree:add(buffer(n,2), "Address:  " .. buffer(n,2):uint()) 				
			subtree:add(buffer(n+2,1), "RSSI: " .. buffer(n+2,1):uint())	
			n=n+3
		end
	end 

--RESPONSE
	if typ == 4 then 
		subtree:add(buffer(10,4), "W1: " .. buffer(10,4):uint())
        subtree:add(buffer(14,4), "W2: " .. buffer(14,4):uint())
        subtree:add(buffer(18,4), "W3: " .. buffer(18,4):uint())
        subtree:add(buffer(22,4), "ACT: " .. buffer(22,4):uint())
        subtree:add(buffer(26,1), "Stat: " .. buffer(26,1):uint())
	end

--OPENPATH
	if typ == 5 then 
		local n = 10
		local i= (buffer:len()-10) /2
		for j =1,i do
			subtree:add(buffer(n,2), "Address: " .. buffer(n,2):uint())
			n=n+2
		end
	end

--CONFIG 
	if typ == 6 then
		subtree:add(buffer(10,2), "Property: " .. buffer(10,2):uint())
	end

-- description of packet
  	subtree:append_text(", Packet details in the tree below")
end 

-- udp.port
udp_table = DissectorTable.get("udp.port")
udp_table:add(20015,sdn_wise_proto)