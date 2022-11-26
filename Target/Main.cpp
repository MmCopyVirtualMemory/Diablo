#include <windows.h>
#include <iostream>
int health = 100;
int shield = 50;




int main() 
{
	while (true) 
	{
		if (GetAsyncKeyState(VK_UP)) 
		{
			health++;
		}
		if (GetAsyncKeyState(VK_DOWN))
		{
			health--;
		}
		std::cout << "=====================" << std::endl;
		std::cout << "Health: " << health << std::endl;
		std::cout << "Shield: " << shield << std::endl;
		Sleep(20);
	}
}