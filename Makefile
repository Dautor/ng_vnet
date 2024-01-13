SRCS=ng_vnet.c
KMOD=ng_vnet

.include <bsd.kmod.mk>

.PHONY: lsp ratl ratu rat rats
lsp:
	bear -- make
ratl: ng_vnet.ko
	@rsync ng_vnet.ko rat:
	@ssh rat kldload ./ng_vnet.ko
ratu:
	@ssh rat kldunload ng_vnet
rat:
	@ssh rat
rats:
	printf 'mkpeer vnet a a\nmsg .a connect 1' | ssh rat ngctl -f -
