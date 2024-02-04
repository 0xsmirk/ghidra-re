
::不导入程序执行，调用已分析的项目执行

::D:\Download\ghidra_11.0_PUBLIC_20231222\ghidra_11.0_PUBLIC\support\analyzeHeadless.bat F:\test tbox_reverse -processor "ARM:LE:32:v8" -process "*" -postScript E:\ghidra-re\plugins-py\CallChain.py popen

::导入待分析的程序，从头开始分析
D:\Download\ghidra_11.0_PUBLIC_20231222\ghidra_11.0_PUBLIC\support\analyzeHeadless.bat F:\test tbox_reverse -import E:\desktop\tbox_net -processor "ARM:LE:32:v8" -postScript E:\ghidra-re\plugins-py\CallChain.py popen
