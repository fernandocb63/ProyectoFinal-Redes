// ConsoleApplication1.cpp : Este archivo contiene la función "main". La ejecución del programa comienza y termina ahí.
//

#include <iostream>
#include <iomanip>
#include "sodium.h"
#include <fstream>
#include <string>
using namespace std;




int main()
{   
    int b;
    std::cout << "Si quieres terminar el programa presiona 0 sino presiona 1 \n";
    cin >> b;
    while (b != 0) {
        std::cout << "Bienvenido \n";
        std::cout << "1.- Generación y Recuperación de Claves hacia o desde 1 archivo \n";
        std::cout << "2.- Cifrado y Decifrado de archivos \n";
        std::cout << "3.- Firma de archivos y verificar la firma \n";
        int x;
        cout << "Escriba una Opcion: \n"; // Type a number and press enter
        cin >> x;
        switch (x) //donde opción es la variable a comparar
        {
        case 1: //Bloque de instrucciones 1;
        {
            char ar[50];
            std::cout << "Seleccione el archivo: \n";
            cin >> ar;
            string ap = "C:\\";
            ap.append(ar);
            std::ifstream inFile;
            unsigned char* cat = new unsigned char[102400];
            inFile.open(ap);
            string sum;
            string x;
            if (inFile.is_open()) {
                inFile.getline((char*)cat, 10240, '\0');
                inFile.close();
            }
            int cat_len = strlen((char*)cat);



            unsigned char pk[crypto_sign_PUBLICKEYBYTES];
            unsigned char sk[crypto_sign_SECRETKEYBYTES];

            crypto_sign_keypair(pk, sk);
            std::cout << "Se generar las llaves \n";
            std::cout << "pk \n",pk;
            std::cout << "sk \n", sk;

            break;
        }
        case 2:
        {
            char ar[50];
            std::cout << "Seleccione el archivo: \n";
            cin >> ar;
            string ap = "C:\\";
            ap.append(ar);
            std::cout << ap;
            std::ifstream inFile;
            unsigned char* cat = new unsigned char[102400];
            inFile.open(ap);
            string sum;
            string x;
            if (inFile.is_open()) {
                inFile.getline((char*)cat, 10240, '\0');
                inFile.close();
            }

            

            inFile.close();
            std::cout << "CIFRADO y DECIFRADO DE ARCHIVOS: \n\n";


            unsigned char plaintext[] = { cat[102400] };

            int plaintext_len = strlen((char*)cat);
            unsigned char* ciphertext = new unsigned char[plaintext_len];
            unsigned char* deciphertext = new unsigned char[plaintext_len];
            unsigned char key[crypto_stream_chacha20_KEYBYTES];
            unsigned char nonc[crypto_stream_chacha20_NONCEBYTES];

            crypto_secretbox_keygen(key);
            randombytes_buf(nonc, sizeof nonc);

            int errorcode = crypto_stream_chacha20_xor(ciphertext, cat, plaintext_len, nonc, key);
            std::cout << "Cifrado:  ";
            for (int i = 0; i < plaintext_len; i++) {
                std::cout << std::setfill('0') << std::setw(2) << std::hex << int(ciphertext[i]);
            }
            std::cout << std::endl;

            errorcode = crypto_stream_chacha20_xor(deciphertext, ciphertext, plaintext_len, nonc, key);
            for (int i = 0; i < plaintext_len; i++) {
                //std::cout << std::setfill('0') << std::setw(2) << std::hex << int(deciphertext[i]);
            }
            std::cout << std::endl;
            std::cout << "Decifrado:  ";

            std::cout << deciphertext;
            std::cout << "\n";
            break;
        }
        case 3:
        {
            char ar[50];
            std::cout << "Seleccione el archivo: \n";
            cin >> ar;
            string ap = "C:\\";
            ap.append(ar);
            std::ifstream inFile;
            unsigned char* cat = new unsigned char[102400];
            inFile.open(ap);
            string sum;
            string x;
            if (inFile.is_open()) {
                inFile.getline((char*)cat, 10240, '\0');
                inFile.close();
            }
            int cat_len = strlen((char*)cat);



            unsigned char pk[crypto_sign_PUBLICKEYBYTES];
            unsigned char sk[crypto_sign_SECRETKEYBYTES];

            unsigned char sig[crypto_sign_BYTES];
            crypto_sign_keypair(pk, sk);


            crypto_sign_detached(sig, NULL, cat, cat_len, sk);

            if (crypto_sign_verify_detached(sig, cat, cat_len, pk) != 0) {
                /* Incorrect signature! */
                std::cout << "No se pudo realizar cone exito\n";
            }
            else {
                std::cout << "Las llaves estas verificadas\n";
            }
            break;
        }
        default:
        {
            break;
        }
        }
    }


    return 0;
}