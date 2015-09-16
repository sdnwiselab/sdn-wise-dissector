-- Esempio parsing SDN-WISE
sdn_wise_proto = Proto("sdn-wise","SDN-WISE Protocol")





-- Dissector
function sdn_wise_proto.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "SDN-WISE"


    local subtree = tree:add(sdn_wise_proto,buffer(),"SDN-WISE Protocol Data")
    
    subtree:add(buffer(0,1),"Length: " .. buffer(0,1):uint())
    subtree:add(buffer(1,1),"Network Id: " .. buffer(1,1):uint())
    subtree:add(buffer(2,2),"Source Address: " .. buffer(2,2):uint())
    subtree:add(buffer(4,2),"Destination Address: " .. buffer(4,2):uint())
    
local typ = buffer(6,1): le_uint() 
    subtree:add(buffer(6,1),"Type: " .. buffer(6,1):uint())


    subtree:add(buffer(7,1),"Time To Live: " .. buffer(7,1):uint())
    subtree:add(buffer(8,2),"Next Hop Address: " .. buffer(8,2):uint())  

--DATA
if typ == 0
then subtree:add(buffer(10,1), "Payload: " .. buffer:len()-10)
end

--BEACON
if typ == 1 
then subtree:add(buffer(10,1), "Dist hop " .. buffer(10,1):uint())
     subtree:add(buffer(11,1), "Batt " .. buffer(11,1):uint())
end

--REPORT
if typ ==2 
then
--local i = (buffer:len() - 13)/3
j = buffer(12,1):uint()

      subtree:add(buffer(10,1), "Dist hop " .. buffer(10,1):uint())
      subtree:add(buffer(11,1), "Batt " .. buffer(11,1):uint())
      subtree:add(buffer(12,1), "Numero vicini: " .. buffer(12,1):uint()) 

	local n = 13

	for i =1,j do
	subtree:add(buffer(n,2), "ADD:  " .. buffer(n,2):uint()) 				subtree:add(buffer(n+2,1), "RSSI: " .. buffer(n+2,1):uint())	
	n=n+3
	end
end 

--RESPONSE
if typ == 4 
then subtree:add(buffer(10,4), "W1 " .. buffer(10,4):uint())
     subtree:add(buffer(14,4), "W2 " .. buffer(14,4):uint())
     subtree:add(buffer(18,4), "W3 " .. buffer(18,4):uint())
     subtree:add(buffer(22,4), "ACT " .. buffer(22,4):uint())
     subtree:add(buffer(26,1), "Stat " .. buffer(26,1):uint())
end

--OPENPATH
if typ == 5
then 
local n = 10
local i= (buffer:len()-10) /2

	for j =1,i do
	subtree:add(buffer(n,2), "Address: " .. buffer(n,2):uint())
	n=n+2
	end
end

--CONFIG 
--sono 2 o 3 byte?? 
--Il	primo	byte	è	un	id	per	identificare	la proprietà
--Il	secondo	e	il	terzo	sono	i	valori	di	tale	proprietà 	
if typ == 6
then subtree:add(buffer(10,2), "Property: " .. buffer(10,2):uint())

end

-- description of packet
  subtree:append_text(", Packet details in the tree below")


end 

-- udp.port
udp_table = DissectorTable.get("udp.port")
udp_table:add(20015,sdn_wise_proto)