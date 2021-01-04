obj-m := core.o

kernel_path := /home/loongson/linux-4.19-loongson
work_path := $(shell pwd)

all:
	make -C $(kernel_path) M=$(work_path) modules
clean:
	make -C $(kernel_path) M=$(work_path) clean

