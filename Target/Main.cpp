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



		Sleep(1000);
	}
}