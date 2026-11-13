#include <stdio.h>

int main(int argc, char **argv, char **envp) {
	const char *filename = argv[1];
	FILE *fd = fopen(filename, "r");

	if (fd == NULL) {
		printf("Could not open: %s\n", filename);
  } else {
		printf("Success\n");
		fclose(fd);
	}
}
