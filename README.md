# machostrip

使用lief对macho进行一些简单操作

## Feat

- 移除所有Function Starts
- 移除所有local symbols和external symbols
- 使Hopper Demo版和Ghidra无法加载文件
- 混淆符号stub名称
 
## Before

![before](before.png)

## After

![after](after.png)
