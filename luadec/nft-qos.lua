1111111111111111111111111111-- Decompiled using luadec 2.2 rev: fd1b70d for Lua 5.1 from https://github.com/viruscamp/luadec
-- Command line: ../../controller/nft-qos.lua 

-- params : ...
-- function num : 0
module("luci.controller.nft-qos", package.seeall)
index = function()
  -- function num : 0_0
  local l_1_0 = entry
  local l_1_1 = {}
  -- DECOMPILER ERROR at PC5: No list found for R1 , SetList fails

  -- DECOMPILER ERROR at PC6: Overwrote pending register: R2 in 'AssignReg'

  -- DECOMPILER ERROR at PC7: Overwrote pending register: R3 in 'AssignReg'

  l_1_0(l_1_1, ("admin")("services"))
  -- DECOMPILER ERROR at PC14: Overwrote pending register: R4 in 'AssignReg'

  l_1_0(l_1_1, cbi("qos/limit"))
  l_1_1 = {"admin", "services", "qos", "limit"}
  -- DECOMPILER ERROR at PC21: Overwrote pending register: R0 in 'AssignReg'

  l_1_0(l_1_1, cbi("qos/priority"))
  l_1_1 = {"admin", "services", "qos", "priority"}
end


