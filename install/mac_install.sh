#!/bin/zsh
# **********************************************************
# * Author      : smile-e3
# * Email       : alchemist_clb@163.com
# * Create time : 2024-03-18
# * Update time : 2024-03-21
# * Filename    : mac_install.sh
# * Description : 自动化安装Ghidra及相关插件
# **********************************************************

# set -x

source common.sh

# Ghidra默认安装路径$HOME
GHIDRA_INSTALL_PATH=$HOME
# Ghidra安装包下载地址
GHIDRA_PACKAGE="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0_build/ghidra_11.0_PUBLIC_20231222.zip"
# 获取下载的ghidra文件名
GHIDRA_PACKAGE_FILENAME=$(basename "$GHIDRA_PACKAGE")
# 获取解压后的目录名
GHIDRA_PATH="${GHIDRA_INSTALL_PATH}/${GHIDRA_PACKAGE_FILENAME%_*}"
# 软件包路径
GHIDRA_INSTALL=$PWD
# Ghidrathon安装目录
GHIDRATHON_PATH=$HOME/Ghidrathon
# Ghidra脚本默认安装路径
GHIDRA_SCRIPTS_PATH=$HOME/ghidra_scripts
# pyenv默认安装路径
# PYENV_PATH=$HOME/.pyenv

#######################################
# 检查Java版本是否为17
# Globals:
#   None
# Arguments:
#   None
# Returns:
#   None
#######################################
check_java_version() {
    java_version=$(java -version 2>&1 | awk -F '"' '/version/ {print $2}')
    if [[ "$java_version" == 17* ]]; then
        echo "True"
    else
        echo "False"
    fi
}

#######################################
# 安装当前项目适配的Ghidra版本
# Globals:
#   GHIDRA_INSTALL_PATH
#   GHIDRA_PACKAGE
#   GHIDRA_PACKAGE_FILENAME
# Arguments:
#   None
# Returns:
#   None
#######################################
ghidra_install(){
    echo "${GREEN}[INFO]开始安装Ghidra${NC}"

    # 判断安装包是否存在，如果存在则删除安装包
    if [ -f "/tmp/${GHIDRA_PACKAGE_FILENAME}" ]; then
        rm /tmp/${GHIDRA_PACKAGE_FILENAME}
    fi

    # 下载Ghidra应用
    wget -P /tmp ${GHIDRA_PACKAGE}

    # 解压安装Ghidra
    unzip /tmp/${GHIDRA_PACKAGE_FILENAME} -d ${GHIDRA_INSTALL_PATH}
    echo "${GREEN}[INFO]Ghidra安装成功${NC}"
}

#######################################
# 安装Ghidrathon
# Globals:
#   None
# Arguments:
#   None
# Returns:
#   None
#######################################
ghidrathon_install(){
    echo "${GREEN}[INFO]开始安装ghidrathon${NC}"

    # 判断pyenv是否存在，默认pyenv的安装路径为$HOME/.pyenv
    command_name="pyenv"
    pyenv_exists=$(check_commands_existence "$command_name")
    if [ "$pyenv_exists" = "pyenv" ]; then
        # 安装pyenv新环境
        git clone https://github.com/pyenv/pyenv.git ~/.pyenv
        echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.zshrc
        echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.zshrc
        echo 'eval "$(pyenv init --path)"' >> ~/.zshrc
        echo 'if command -v pyenv >/dev/null; then eval "$(pyenv init -)"; fi' >> ~/.zshrc
    fi

    # 判断安装包是否存在，如果存在则删除安装包
    if [ -f "/tmp/Ghidrathon-v4.0.0.zip" ]; then
        rm /tmp/Ghidrathon-v4.0.0.zip
    fi
    # 安装Ghidrathon工具
    wget -P /tmp https://github.com/mandiant/Ghidrathon/releases/download/v4.0.0/Ghidrathon-v4.0.0.zip    
    mkdir $GHIDRATHON_PATH && unzip -d $GHIDRATHON_PATH /tmp/Ghidrathon-v4.0.0.zip

    # 使用pyenv创建新环境
    cd $GHIDRATHON_PATH && ~/.pyenv/bin/pyenv install -v 3.9.0 && ~/.pyenv/bin/pyenv local 3.9.0

    # 在Ghidrathon目录下安装相关
    if [ "$pyenv_exists" = "True" ]; then
        pyenv exec python -m pip install -r requirements.txt
        pyenv exec python ghidrathon_configure.py ${GHIDRA_PATH} && cp -rf Ghidrathon-v4.0.0.zip ${GHIDRA_PATH}/Extensions/Ghidra
    else
        ~/.pyenv/bin/pyenv exec python -m pip install -r requirements.txt
        ~/.pyenv/bin/pyenv exec python ghidrathon_configure.py ${GHIDRA_PATH} && cp -rf Ghidrathon-v4.0.0.zip ${GHIDRA_PATH}/Extensions/Ghidra
    fi

    echo "${GREEN}[INFO]Ghidrahon安装成功,需要运行Ghidra手动启动Ghidrahon扩展${NC}"
}

#######################################
# 安装当前具有的插件
# Globals:
#   None
# Arguments:
#   None
# Returns:
#   None
#######################################
ghidra_scripts_install(){

    # 将ghidra的python插件复制到Ghidra的默认路径下
    cp -rf ${GHIDRA_INSTALL}/../plugins-py/* $HOME/ghidra_scripts/

    # 检查命令返回状态
    if [ $? -eq 0 ]; then
        echo "${GREEN}[INFO]Ghidra 插件安装成功${NC}"
    else
        echo "${RED}复制失败${NC}"
        # 添加重试机制或其他处理逻辑
    fi

    if [ ! -d "$GHIDRA_SCRIPTS_PATH" ]; then
        mkdir $GHIDRA_SCRIPTS_PATH
    fi
    
    # 将ghidra的java插件安装到路径下
    cp -rf ${GHIDRA_INSTALL}/../plugins-java/* $GHIDRA_SCRIPTS_PATH
}

#######################################
# 打印Banner
# Globals:
#   None
# Arguments:
#   None
# Returns:
#   None
#######################################
banner(){
    echo "   ____ _     _     _                 ____      "
    echo "  / ___| |__ (_) __| |_ __ __ _      |  _ \ ___ "
    echo " | |  _| '_ \| |/ _\` | '__/ _\` |_____| |_) / _ \\"
    echo " | |_| | | | | | (_| | | | (_| |_____|  _ <  __/"
    echo "  \____|_| |_|_|\__,_|_|  \__,_|     |_| \_\___|"
    echo "                                                "
    echo "                                     by smile-e3"
}

#######################################
# 函数：主函数入口
# Globals:
#   GHIDRA_PATH
#   GHIDRATHON_PATH
#   PYENV_PATH
# Arguments:
#   None
# Returns:
#   None
#######################################
main(){

    # step0:打印Banner
    banner

    # step1:依赖检测(工具、文件夹等)
    # 判断JAVA17是否安装
    if [ "$(check_java_version)" = "False" ]; then
        echo "${RED}[ERROR]JAVA 17不存在,请安装${NC}"
        exit
    fi

    # 判断依赖工具是否存在
    tool_dependencies=("brew" "wget" "unzip" "git")
    # 调用函数检查命令是否存在，并打印结果
    result=$(check_commands_existence "${tool_dependencies[@]}")
    if [ "$result" = "True" ]; then
        echo "${GREEN}[INFO]依赖工具都已安装${NC}"
    else
        echo "以下命令未安装："
        for cmd in $result
        do
            if [ "$cmd" = "brew" ]; then
                echo "${RED}[ERROR]brew不存在,请安装${NC}"
                exit
            else
                echo "$cmd"
                #TODO:如果brew命令安装功能存在需要判断
                brew install ${cmd}
            fi
        done
    fi

    # 判断相关应用文件夹是否存在
    folders=("${GHIDRA_PATH}" "${GHIDRATHON_PATH}")
    # 调用函数检查文件夹是否存在，并打印结果
    folder_result=$(check_folders_existence "${folders[@]}")
    if [ "$folder_result" = "True" ]; then
        for old_folder in $folders
            do 
                echo "正在删除文件夹".$old_folder
                rm -rf $old_folder
            done
            echo $old_folder
    fi



    # step1:安装Ghidra逆向分析工具
    ghidra_install

    # step2:编译安装Ghidrathon第三方python脚本运行插件
    ghidrathon_install

    # step3:将Ghidra的插件安装到MAC默认的路径
    ghidra_scripts_install
}

main