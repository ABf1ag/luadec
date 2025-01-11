local test = require('test')
local data = string.dump(test)

local fp = io.open("test.luac","wb")
fp:write(data)
fp:close()