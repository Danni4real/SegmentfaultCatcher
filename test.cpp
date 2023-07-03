#include <exception>

#include "SegmentfaultCatcher.h"

void create_segmentfault()
{
	int* x = 0;
	*x = 0;
}

void throw_exception()
{
	throw 100;
}


int main()
{
	SegmentfaultCatcher::Register();
	
	throw_exception();
	
	//crash();
	
	return 0;
}
