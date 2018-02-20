-- SDN-WISE Protocol Dissector
-- Authors: S. Milardo - M. Fede - Y. Trapani

sdn_wise_proto = Proto("sdn-wise", "SDN-WISE Protocol")
id = ProtoField.uint8("sdn-wise.id", "Network Id", base.DEC)
len = ProtoField.uint8("sdn-wise.len", "Lenght", base.DEC)
dst = ProtoField.uint16("sdn-wise.dst", "Destination Address", base.DEC)
src = ProtoField.uint16("sdn-wise.src", "Source Address", base.DEC)
typ = ProtoField.uint8("sdn-wise.typ", "Type", base.DEC)
ttl = ProtoField.uint8("sdn-wise.ttl", "Time To Live", base.DEC)
nxhop = ProtoField.uint16("sdn-wise.nxhop", "Next Hop Address", base.DEC)

sdn_wise_proto.fields = { id, len, dst, src, typ, ttl, nxhop }

-- Dissector
function sdn_wise_proto.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end
    pinfo.cols.protocol = sdn_wise_proto.name

    if (tostring(pinfo.dl_dst) == "Broadcast") then
        offset = 4
    else
        offset = 6
    end
    
    subtree = tree:add(sdn_wise_proto, buffer(0))
    
    subtree:add_le(id, buffer(offset + 0, 1))
    subtree:add_le(len, buffer(offset + 1, 1))
    subtree:add(dst, buffer(offset + 2, 2))
    subtree:add(src, buffer(offset + 4, 2))
    subtree:add_le(typ, buffer(offset + 6, 1))
    subtree:add_le(ttl, buffer(offset + 7, 1))
    subtree:add(nxhop, buffer(offset + 8, 2))
    local typ = buffer(offset + 6, 1):le_uint()

    --DATA
    if typ == 0 then
        subtree:add(buffer(offset + 10, 1), "Payload: " .. buffer(offset + 10, 1):uint())
    end

    --BEACON
    if typ == 1 then
        subtree:add(buffer(offset + 10, 1), "Dist. hop: " .. buffer(offset + 10, 1):uint())
        subtree:add(buffer(offset + 11, 1), "Batt: " .. buffer(offset + 11, 1):uint())
    end

    --REPORT
    if typ == 2 then
        subtree:add(buffer(offset + 10, 1), "Dist. hop: " .. buffer(offset + 10, 1):uint())
        subtree:add(buffer(offset + 11, 1), "Battery: " .. buffer(offset + 11, 1):uint())
        subtree:add(buffer(offset + 12, 1), "Neighbours: " .. buffer(offset + 12, 1):uint())

        j = buffer(offset + 12, 1):uint()
        local n = offset + 13
        for i = 1, j do
            subtree:add(buffer(n, 2), "Address:  " .. buffer(n, 2):uint())
            subtree:add(buffer(n + 2, 1), "RSSI: " .. buffer(n + 2, 1):uint())
            n = n + 3
        end
    end

    --REQUEST
    if typ == 3 then
        subtree:add(buffer(offset + 10, 1), "Id: " .. buffer(offset + 10, 1):uint())
        subtree:add(buffer(offset + 11, 1), "Part: " .. buffer(offset + 11, 1):uint())
        subtree:add(buffer(offset + 12, 1), "Total: " .. buffer(offset + 12, 1):uint())
    end

    --RESPONSE
    if typ == 4 then
        subtree:add(buffer(offset + 10, 4), "W1: " .. buffer(offset + 10, 4):uint())
        subtree:add(buffer(offset + 14, 4), "W2: " .. buffer(offset + 14, 4):uint())
        subtree:add(buffer(offset + 18, 4), "W3: " .. buffer(offset + 18, 4):uint())
        subtree:add(buffer(offset + 22, 4), "ACT: " .. buffer(offset + 22, 4):uint())
        subtree:add(buffer(offset + 26, 1), "Stat: " .. buffer(offset + 26, 1):uint())
    end

    --OPENPATH
    if typ == 5 then
        local w = buffer(offset + 10, 1):uint()
        subtree:add(buffer(offset + 10, 1), "Windows: " .. w)

        local k = 0
        for k = 1, w do
            subtree:add(buffer(offset + 11 + k*4, 4), "Window: " .. buffer(offset + 11 + k*4, 4):uint())
        end

        local n = offset + 11 + (k*4)
        local i = (buffer:len() - n) / 2

        for j = 1, i do
            subtree:add(buffer(n, 2), "Address: " .. buffer(n, 2):uint())
            n = n + 2
        end
    end

    --CONFIG
    if typ == 6 then
        subtree:add(buffer(offset + 10, 2), "Property: " .. buffer(offset + 10, 2):uint())
    end

    -- description of packet
    subtree:append_text(", Packet details in the tree below")
end

-- if sdn-wise is encapsulated into an udp packet (NOTE: change offset to 0)
--      udp_table = DissectorTable.get("udp.port")
--      udp_table:add(20015,sdn_wise_proto)
-- if sdn-wise packets come directly from Cooja (NOTE: change the offset accordingly)
--      table = DissectorTable.get("wtap_encap")
--      table:add(104, sdn_wise_proto)
--      table:add(127, sdn_wise_proto)
-- if sdn-wise is on top of TSCH
        sdn_wise_proto:register_heuristic("wpan", sdn_wise_proto.dissector) -- postdissector 802.15.4 data

-- Initialization routine
function sdn_wise_proto.init()
end