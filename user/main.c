#include <stdio.h>
void get_data()
{
		FILE *fptr = NULL;
		int blocked=0, passed=0, total=0;
		fptr = fopen("/sys/class/my_class2/my_class2_My_Device1/my_att", "r");
		if (!fptr)
		{
			printf("Driver not exist\n");
			return;
		}
		fscanf(fptr, "%d", &blocked);
		fscanf(fptr, "%d", &passed);
		total = passed + blocked;
		printf("Firewall Packet Summary:\n");
		printf("Number of accepted packets: %d\n", passed);
		printf("Number of dropped packets: %d\n", blocked);
		printf("Total number of packets: %d\n", total);
		fclose(fptr);
}
void reset()
{
	FILE *fptr = NULL;
	fptr = fopen("/sys/class/my_class2/my_class2_My_Device1/my_att", "w");
	if (!fptr)
	{
		printf("Driver not exist\n");
		return;
	}
	fprintf(fptr, "%c", 0);
	fclose(fptr);
}
int main(int argc, char** argv)
{
	if ((argc > 2) || ((argc == 2) && (strcmp(argv[1], "0") != 0)))
	{
		printf("usage: %s [0]\n", argv[0]);
	}
	else if(argc == 1)
		get_data();
	else
		reset();
	return 0;
	
}
