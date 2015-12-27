obj-m += fw.o
fw-objs := rule_table.o log_table.o module_main.o conn_table.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
