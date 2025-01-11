local bit = require('bit')
local test = require('test')

-- ���������� lua �� dump �ļ� 
-- test.luac 标准lua编译 
local fp = io.open("test.luac", "rb")
local ori_data = fp:read("*all")
fp:close()

-- print('data len '.. #data)
-- print('ori_data len ' .. #ori_data)

-- 标准op_name顺序
local ori_op_name = {"GETTABLE", "GETGLOBAL", "SETGLOBAL", "SETUPVAL", "SETTABLE", "NEWTABLE", "SELF", "LOADNIL",
                     "LOADK", "LOADBOOL", "GETUPVAL", "LT", "LE", "EQ", "DIV", "MUL", "SUB", "ADD", "MOD", "POW", "UNM",
                     "NOT", "LEN", "CONCAT", "JMP", "TEST", "TESTSET", "MOVE", "FORLOOP", "FORPREP", "TFORLOOP",
                     "SETLIST", "CLOSE", "CLOSURE", "CALL", "RETURN", "TAILCALL", "VARARG"}
local data = string.dump(test) -- dump

local new_op = {}
-- ��Ŀ�� lua ������ lua �� dump ���ݶԱ�
for i = 1, #data do
    local by_ori = string.byte(ori_data, i)
    local by_new = string.byte(data, i)
    -- print(by_new)
    if by_ori ~= by_new then
        -- print(by_ori)
        local op_name = ori_op_name[bit:_and(0x3F, by_ori) + 1]
        local op_idx = bit:_and(0x3F, by_new)
        print(op_name)
        new_op[op_name] = op_idx
    end
end

print("old \t new \t name")
for idx, op_name in pairs(ori_op_name) do
    local tmp = ''
    if new_op[op_name] ~= nil then
        tmp = new_op[op_name]
    end
    print((idx - 1) .. "\t" .. tmp .. "\t" .. op_name)
end

-- 将 `new_op` 转换为一个可排序的列表
local sorted_ops = {}
for op_name, op_idx in pairs(new_op) do
    table.insert(sorted_ops, {
        op_name = op_name,
        op_idx = op_idx
    })
end

-- 按 `op_idx` 从 0 到 1 排序
table.sort(sorted_ops, function(a, b)
    return a.op_idx < b.op_idx
end)

-- 输出根据 `new_op` 排序后的操作码
print("new \t name")
for _, op in ipairs(sorted_ops) do
    print(op.op_idx .. "\t" .. op.op_name)
end
