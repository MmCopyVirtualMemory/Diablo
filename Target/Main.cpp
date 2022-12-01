#include <windows.h>
#include <iostream>

void Vf() 
{
	std::cout << "hello" << std::endl;
}

void(*dataPtr)() = Vf;


int main() 
{
	while (true) 
	{
		std::cout << &dataPtr << " -> " << dataPtr << std::endl;
		dataPtr();

		


		void* mem = VirtualAlloc(0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		VirtualFree(mem, 0, MEM_RELEASE);
	}
}