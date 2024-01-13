SRCS=ng_vnet_hub.c
KMOD=ng_vnet_hub

.include <bsd.kmod.mk>

.PHONY: lsp ratl ratu rat rats
lsp:
	bear -- make
ratl: ng_vnet_hub.ko
	@rsync ng_vnet_hub.ko rat:
	@ssh rat kldload ./ng_vnet_hub.ko
ratu:
	@ssh rat kldunload ng_vnet_hub
rat:
	@ssh rat
