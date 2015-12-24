all:
	gcc -o main.out main.c
	gcc -o load_rules.out load_rules.c
	gcc -o show_rules.out show_rules.c
	gcc -o show_logs.out show_logs.c
	gcc -Wall -o test stateful.c -lnfnetlink -lnetfilter_queue
clean:
	rm main.out
	rm load_rules.out
	rm show_rules.out
	rm show_logs.out
	rm stateful.out
