# Must be invoked w/ -ExecutionPolicy Bypass. Requires Powershell 5.0+.

(gwmi -list win32_shadowcopy).Create('C:\','ClientAccessible')
(gwmi -list win32_shadowcopy).Create('E:\','ClientAccessible')

# vim:ff=dos ft=sh tw=0
