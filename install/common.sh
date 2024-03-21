#!/bin/zsh
# **********************************************************
# * Author      : smile-e3
# * Email       : alchemist_clb@163.com
# * Create time : 2024-03-20
# * Update time : 2024-03-21
# * Filename    : common.sh
# * Description : shell通用库,包含log输出、文件检测等
# **********************************************************

# set -x

# 设置颜色
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
BLUE=$(tput setaf 4)
NC=$(tput sgr0) # 重置颜色

#######################################
# 检查命令是否存在
# Globals:
#   None
# Arguments:
#   commands
# Returns:
#   bool:True
#   array:missing_commands
#######################################
check_commands_existence() {
    local missing_commands=()
    local commands=("$@")
    
    for cmd in "${commands[@]}"
    do
        if ! command -v "$cmd" &>/dev/null; then
            missing_commands+=("$cmd")
        fi
    done
    
    if [ ${#missing_commands[@]} -eq 0 ]; then
        echo "True"
    else
        echo "${missing_commands[@]}"
    fi
}

#######################################
# 检查文件夹是否存在
# Globals:
#   None
# Arguments:
#   folders
# Returns:
#   bool:True
#   array:missing_folders
#######################################
check_folders_existence() {
    local folders=("$@")
    local missing_folders=()

    for folder in "${folders[@]}"
    do
        if [ ! -d "$folder" ]; then
            missing_folders+=("$folder")
        fi
    done

    if [ ${#missing_folders[@]} -eq 0 ]; then
        echo "True"
    else
        echo "${missing_folders[@]}"
    fi
}