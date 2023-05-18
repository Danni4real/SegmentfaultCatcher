#include "SegmentfaultCatcher.h"

void crash()
{
	int* x = 0;
	*x = 0;
}

int main()
{
	SegmentfaultCatcher::Register();
	
	crash();
	
	return 0;
}
