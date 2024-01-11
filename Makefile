SRCS=ng_vnet.c
KMOD=ng_vnet

.include <bsd.kmod.mk>

.PHONY: lsp ratl ratu rat
lsp:
	bear -- make
ratl: ng_vnet.ko
	@rsync ng_vnet.ko rat:
	@ssh rat kldload ./ng_vnet.ko
ratu: ng_vnet.ko
	@ssh rat kldunload ng_vnet
rat:
	@ssh rat
