#!/bin/bash

# ==============================================================================
# decompile_to_dir.sh
#
# 递归地查找源目录中的所有 .lua 文件，运行 luadec，
# 并将输出保存到目标目录，同时保持原始的目录结构。
#
# 用法:
#   ./decompile_to_dir.sh <源目录> <目标目录>
#
# 示例:
#   ./decompile_to_dir.sh ./lua_source ./lua_decompiled
#
# ==============================================================================

# --- 配置 ---
# luadec 可执行文件的路径。假定它在当前脚本所在的目录中。
LUADEC_CMD="./luadec/luadec/luadec"


# --- 脚本开始 ---

# 检查是否提供了两个参数
if [ "$#" -ne 2 ]; then
  echo "错误: 需要提供源目录和目标目录两个参数。"
  echo "用法: $0 <源目录> <目标目录>"
  exit 1
fi

SOURCE_DIR="$1"
DEST_DIR="$2"

# 检查源目录是否存在
if [ ! -d "$SOURCE_DIR" ]; then
  echo "错误: 源目录 '$SOURCE_DIR' 不存在。"
  exit 1
fi

# 检查 luadec 命令是否存在且可执行
if [ ! -x "$LUADEC_CMD" ]; then
  echo "错误: 未找到 '$LUADEC_CMD' 命令，或者它没有执行权限。"
  echo "请确保 luadec 可执行文件与此脚本位于同一目录，并已通过 'chmod +x luadec' 赋予权限。"
  exit 1
fi

# 如果目标目录不存在，则创建它
if [ ! -d "$DEST_DIR" ]; then
  echo "目标目录 '$DEST_DIR' 不存在，正在创建..."
  mkdir -p "$DEST_DIR"
fi

echo "从 '$SOURCE_DIR' 反编译 .lua 文件到 '$DEST_DIR'..."
echo "================================================================="

# 使用 find 查找所有 .lua 文件
find "$SOURCE_DIR" -type f -name "*.lua" -print0 | while IFS= read -r -d '' source_file; do
  
  # 1. 计算相对于源目录的路径
  #    例如，将 "/path/to/source/subdir/script.lua" 变为 "subdir/script.lua"
  relative_path="${source_file#$SOURCE_DIR/}"
  
  # 2. 构建完整的目标文件路径
  dest_file="$DEST_DIR/$relative_path"
  
  # 3. 获取目标文件所在的目录
  #    例如，从 "/path/to/dest/subdir/script.lua" 获取 "/path/to/dest/subdir"
  dest_subdir=$(dirname "$dest_file")
  
  # 4. 创建目标子目录 (如果尚不存在)
  #    -p 选项可以确保创建所有必需的父目录，且如果目录已存在也不会报错
  mkdir -p "$dest_subdir"
  
  # 5. 执行反编译并将输出重定向到目标文件
  echo "处理: $source_file"
  if "$LUADEC_CMD" "$source_file" > "$dest_file"; then
    echo "  -> 已保存到: $dest_file"
  else
    echo "  !! 错误: 反编译 '$source_file' 失败。"
    # 如果失败，可以选择删除可能已创建的空目标文件
    rm -f "$dest_file"
  fi
  
done

echo "================================================================="
echo "所有 .lua 文件处理完毕。"