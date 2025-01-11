import struct
def loadVar(f,size):
    Var = f.read(size)
    return Var

def loadHeader(f):
    f.read(12)

def loadFileName(f):
    FileNameSize = struct.unpack('<I', loadVar(f,4))[0]
    FileName = f.read(FileNameSize)
    
def loadHead(f):
    loadHeader(f)
    loadFileName(f)
    f.read(12)

def loadCodeNum(f):
    CodeNum = struct.unpack('<I', loadVar(f,4))[0]
    return CodeNum



# 读取二进制文件
def read_binary_file(filename):
    with open(filename, "rb") as file:
        return file.read()

# 将每4字节的内容解码为对应的整数
def decode_4_bytes(binary_data):
    return [struct.unpack('<I', binary_data[i:i+4])[0] for i in range(0, len(binary_data), 4)]

# 构建替换映射表
def create_replacement_map(file1, file2):
    # 读取并解码两个二进制文件
    fd1 = open(file1,"rb")
    fd2 = open(file2,"rb")

    # 读取头部数据

    loadHead(fd1)
    CodeNum1 = loadCodeNum(fd1)
    data1=fd1.read(CodeNum1*4)
    loadHead(fd2)
    CodeNum2 = loadCodeNum(fd2)
    data2=fd2.read(CodeNum2*4)
    
    # 解码每4字节的数据
    decoded_data1 = decode_4_bytes(data1)
    print("aaaa:",decoded_data1)
    print("\n")
    
    decoded_data2 = decode_4_bytes(data2)
    print("bbb:",decoded_data2)
    # 创建映射：file1中的4字节 -> file2中的4字节
    replacement_map = dict(zip(decoded_data1, decoded_data2))
    fd1.close()
    fd2.close()
    
    return replacement_map

# 使用替换映射替换目标文件中的内容
def replace_in_file(target_file, replacement_map):
    # 读取目标文件
    target_file_fd = open(target_file,"rb")

    # 读取头部数据

    loadHead(target_file_fd)
    CodeNum1 = loadCodeNum(target_file_fd)
    target_data = target_file_fd.read(CodeNum1*4)
    #target_data = read_binary_file(target_file)
    
    # 将目标文件内容按照4字节为单位进行处理
    target_decoded = decode_4_bytes(target_data)
    
    # 创建一个新的字节流用于存放替换后的数据
    new_data = bytearray()
    
    # 遍历并替换
    for value in target_decoded:
        # 如果替换映射中有这个值，就替换
        if value in replacement_map:
            new_data.extend(struct.pack('<I', replacement_map[value]))
        else:
            # 否则原样添加
            new_data.extend(struct.pack('<I', value))
    
    target_file_fd.close()
    # 返回替换后的数据
    return new_data

# 保存替换后的数据到文件
def save_to_file(filename, data):
    with open(filename, "wb") as file:
        file.write(data)

# 主函数
def main(file1, file2, target_file, output_file):

    # 创建替换映射
    replacement_map = create_replacement_map(file1, file2)
    print(replacement_map)
    # 使用映射替换目标文件中的内容
    replaced_data = replace_in_file(target_file, replacement_map)

    
    # 将替换后的数据保存到新文件
    save_to_file(output_file, replaced_data)
    print(f"替换后的文件已保存到: {output_file}")

# 示例文件路径
file1 = "test_m.luac"  # 请替换为第一个文件路径
file2 = "test_o.luac"  # 请替换为第二个文件路径
target_file = "dispatcher.lua"  # 请替换为待替换的目标文件路径
output_file = "output_file.luac"  # 替换后的文件路径

# 执行主函数
main(file1, file2, target_file, output_file)