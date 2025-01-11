function compileLuaToLuac(inputFile, outputFile)
    -- 加载 Lua 文件（返回一个函数）
    -- local chunk, err = loadfile(inputFile)
    -- if not chunk then
    --     print("Error loading file: " .. err)
    --     return false
    -- end

    -- 将加载的函数编译为二进制字符串
    local chunk = require('test')
    local binary = string.dump(chunk)

    -- 将二进制字符串写入输出文件
    local file, err = io.open(outputFile, "wb") -- 使用 "wb" 模式写二进制文件
    if not file then
        print("Error opening output file: " .. err)
        return false
    end

    file:write(binary)
    file:close()
    print("Successfully compiled " .. inputFile .. " to " .. outputFile)
    return true
end

-- 示例调用
local inputLuaFile = "test.lua" -- 输入的 Lua 脚本文件
local outputLuacFile = "test.luac" -- 输出的二进制文件

compileLuaToLuac(inputLuaFile, outputLuacFile)
