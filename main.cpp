#include<iostream>
#include"menu.h"
#include"encrypt.h"
#include"decrypt.h"

using namespace std;

int main()
{
    int choices;
    
    showmenu();
    
    cout<<"Enter your choice : ";
    cin>>choices;
    switch(choices)
    {
        case 1:
            encryptFile();
            break;
        case 2:
            decryptFile();
            break;
        case 3:
            cout<<"Thankyou for choosing AEGISVAULT encryption module..."<<endl;
            break;
        default:
            cout<<"Invalid choice..."<<endl;
    }
    return 0;
}