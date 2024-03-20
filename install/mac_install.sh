#!/bin/zsh
# **********************************************************
# * Author      : smile-e3
# * Email       : alchemist_clb@163.com
# * Create time : 2024-03-18
# * Update time : 2024-03-18
# * Filename    : mac_install.sh
# * Description : 自动化安装Ghidra及相关插件
# **********************************************************

# set -x

# 设置颜色
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
BLUE=$(tput setaf 4)
NC=$(tput sgr0) # 重置颜色

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

# 函数：检查命令是否存在
# 参数：$1 - 要检查的命令名称
# 返回值：True - 如果命令存在，False - 如果命令不存在
check_command_exists() {
    if command -v "$1" &> /dev/null; then
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

    # dependency tools: wget unzip
    wget -P /tmp ${GHIDRA_PACKAGE}

    # 判断Ghidra的安装文件是否存在
    if [ -f "${GHIDRA_PATH}" ]; then
        rm -rf ${GHIDRA_PATH}
    fi
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
    pyenv_exists=$(check_command_exists "$command_name")
    if [ "$pyenv_exists" = "False" ]; then
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
    mkdir $HOME/Ghidrathon && unzip -d $HOME/Ghidrathon /tmp/Ghidrathon-v4.0.0.zip

    # 使用pyenv创建新环境
    cd $HOME/Ghidrathon && ~/.pyenv/bin/pyenv install -v 3.9.0 && ~/.pyenv/bin/pyenv local 3.9.0

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

    echo ${GHIDRA_INSTALL}

    # 将ghidra的python插件复制到Ghidra的默认路径下
    cp -rf ${GHIDRA_INSTALL}/../plugins-py/* $HOME/ghidra_scripts/

    # 检查命令返回状态
    if [ $? -eq 0 ]; then
        echo "${GREEN}[INFO]Ghidra 插件安装成功${NC}"
    else
        echo "${RED}复制失败${NC}"
        # 添加重试机制或其他处理逻辑
    fi

    # 将ghidra的java插件安装到路径下
    cp -rf ${GHIDRA_INSTALL}/../plugins-java/* $HOME/ghidra_scripts/
}

#######################################
# 生成Banner
# Globals:
#   None
# Arguments:
#   None
# Returns:
#   None
#######################################
banner(){
    # 判断figlet是否存在
    command_name="figlet"
    figlet_exists=$(check_command_exists "$command_name")
    if [ "$figlet_exists" = "False" ]; then
        brew install figlet
    fi
    banner_string=$(figlet -f "doom" "Ghidra-Re")
    echo "$banner_string"
    echo "                                     by smile-e3"
}

# 函数：主函数入口
main(){
    # step0:打印Banner
    banner

    # step1:安装Ghidra逆向分析工具
    ghidra_install

    # step2:编译安装Ghidrathon第三方python脚本运行插件
    ghidrathon_install

    # step3:将Ghidra的插件安装到MAC默认的路径
    ghidra_scripts_install
}

main