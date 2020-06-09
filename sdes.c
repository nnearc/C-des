/* sdes.c -- All functions related the Simplified DES Cipher.
 * Copyright (C) 2019 Nearchos Nearchou
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/** @file sdes.c
 *  @brief All functions related the Simplified DES Cipher.
 *
 *  @autor Nearchos Nearchou
 *  @bug No bugs, we used a good spray to kill them.
 */

/* Libraries */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

/* Define Macros */
#define PUBLIC  // Visible out of file
#define PRIVATE static  // Visible only in file

/* Declarations */
int S0[4][4] = {{1,0,3,2},
                {3,2,1,0},
                {0,2,1,3},
                {3,1,3,2}};

int S1[4][4] = {{0,1,2,3},
                {2,0,1,3},
                {3,0,1,0},
                {2,1,0,3}};

/* Function Prototypes */
PRIVATE int *initialPermutation(int[]);
PRIVATE int *finalPermutation(int*);
PRIVATE int *expansionPermutation(int*);
PRIVATE int *P4(int*);
PRIVATE int *P8(int*);
PRIVATE int *P10(int*);
PUBLIC int *leftShift(int*);
PRIVATE int* switchArray(int*, int);
PRIVATE int *splitArray(int*, int, int);
PUBLIC int *mergeArrays(int*, int, int*, int);
PRIVATE int *XOR_Arrays(int*, int*, int);
PUBLIC int convertBinaryToDecimal(int);
PUBLIC int *convertDecimalToBinary(int, int);
PRIVATE int s_box(int*, int);
PRIVATE int *function_with_key(int*, int*, int);
PRIVATE void readArguments(int[], int[], int, char**);
PUBLIC void printArray(int[], int);
PUBLIC int main(int, char**);

/** @brief Rearranges the array according to the Initial Permutation order.
 *
 *  @param plaintext The plaintext
 *  @return The Initial Permutation Array
 */
PRIVATE int *initialPermutation(int plaintext[]) {
  /* Variables */
  int *IP = (int*) malloc(sizeof(int) * 8);

  IP[0] = plaintext[1];
  IP[1] = plaintext[5];
  IP[2] = plaintext[2];
  IP[3] = plaintext[0];
  IP[4] = plaintext[3];
  IP[5] = plaintext[7];
  IP[6] = plaintext[4];
  IP[7] = plaintext[6];

#ifdef DEBUG
  printf("IP: "); printArray(IP, 8);
#endif

  return IP;
}

/** @brief Rearranges the array according to the Final Permutation order (P^-1).
 *
 *  @param array The Array to convert
 *  @return The CipherText
 */
PRIVATE int *finalPermutation(int *array) {
  /* Variables */
  int *FP = (int*) malloc(sizeof(int) * 8);

  FP[0] = array[3];
  FP[1] = array[0];
  FP[2] = array[2];
  FP[3] = array[4];
  FP[4] = array[6];
  FP[5] = array[1];
  FP[6] = array[7];
  FP[7] = array[5];

#ifdef DEBUG
  printf("***********************Final Permutation*************************\n");
  printf("FP: "); printArray(FP, 8);
  printf("*****************************************************************\n");
#endif

  return FP;
}

/** @brief Rearranges the array according to the Expansion Permutation order.
 *
 *  @param array The Array to rearrange
 *  @return The new rearragned Array
 */
PRIVATE int *expansionPermutation(int *array) {
  /* Variables */
  int *EP = (int*) malloc(sizeof(int) * 8);

  EP[0] = array[3];
  EP[1] = array[0];
  EP[2] = array[1];
  EP[3] = array[2];
  EP[4] = array[1];
  EP[5] = array[2];
  EP[6] = array[3];
  EP[7] = array[0];

  return EP;
}

/** @brief Rearranges the array according to the P4 order.
 *
 *  @param array The Array to rearrange
 *  @return The new rearragned Array
 */
PRIVATE int *P4(int *array) {
  /* Variables */
  int *p = (int*) malloc(sizeof(int) * 4);

  p[0] = array[1];
  p[1] = array[3];
  p[2] = array[2];
  p[3] = array[0];

  return p;
}

/** @brief Rearranges the array according to the P8 order.
 *
 *  @param array The Array to rearrange
 *  @return The new rearragned Array
 */
PRIVATE int *P8(int *array) {
  /* Variables */
  int *p = (int*) malloc(sizeof(int) * 8);

  p[0] = array[5];
  p[1] = array[2];
  p[2] = array[6];
  p[3] = array[3];
  p[4] = array[7];
  p[5] = array[4];
  p[6] = array[9];
  p[7] = array[8];

  return p;
}

/** @brief Rearranges the array according to the P10 order.
 *
 *  @param array The Array to rearrange
 *  @return The new rearragned Array
 */
PRIVATE int *P10(int *array) {
  /* Variables */
  int *p = (int*) malloc(sizeof(int) * 10);

  p[0] = array[2];
  p[1] = array[4];
  p[2] = array[1];
  p[3] = array[6];
  p[4] = array[3];
  p[5] = array[9];
  p[6] = array[0];
  p[7] = array[8];
  p[8] = array[7];
  p[9] = array[5];

  return p;
}

/** @brief Shift the 5-bit Array Left once.
 *
 *  @param array The Array to shift
 *  @return The new shifted Array
 */
PUBLIC int *leftShift(int *array) {
  /* Variables */
  int *p = (int*) malloc(sizeof(int) * 5);

  p[0] = array[1];
  p[1] = array[2];
  p[2] = array[3];
  p[3] = array[4];
  p[4] = array[0];

  return p;
}

/** @brief Switch Array MSB with LSB.
 *
 *  @param array The Array to switch
 *  @return The new switched Array
 */
PRIVATE int* switchArray(int *array, int size) {
  /* Variables */
  int *p = (int*) malloc(sizeof(int) * size);
  int i = 0 + size / 2, k;

  for(k = 0; k < size; k++) {
    p[k] = array[i % size];
    i++;
  }

#ifdef DEBUG
  printf("****************************Switch*******************************\n");
  printf("Switch: "); printArray(p, 8);
#endif

  return p;
}

/** @brief Splits the Array in the middle.
 *
 *  @param array The Array to split
 *  @param size The size of the Array
 *  @param left If 1 the split on Least Signifigant Bits(LSB), if 0 on MSB.
 *  @return The new split Array
 */
PRIVATE int *splitArray(int *array, int size, int left) {
  /* Variables */
  int i = size / 2;
  int j = 0, k = 0;
  int *newArray = (int*) malloc(sizeof(int) * i);

  // Check where to start
  if(!left)
    j = i;

  // Set new Array
  for(; k < i; k++) {
    newArray[j % i] = array[j];
    j++;
  }

  return newArray;
}

/** @brief Merge the two given Arrays into one.
 *
 *  @param a1 The first Array
 *  @param s1 The size of the first Array
 *  @param a2 The second Array
 *  @param s2 The size of the second Array
 *  @return The new merged Array
 */
PUBLIC int *mergeArrays(int *a1, int s1, int *a2, int s2) {
  /* Variables */
  int *a = (int*) malloc(sizeof(int) * (s1 + s2));
  int i;

  for(i = 0; i < s1; i++)
    a[i] = a1[i];
  for(; i < s1+s2; i++)
    a[i] = a2[i-s1];

  return a;
}

/** @brief Uses Exclusive-OR with the two given Arrays to create a new Array.
 *
 *  @param a The first Array
 *  @param b The second Array
 *  @param size The size of the Arrays
 *  @return A new Array wih the result of a XOR b
 */
PRIVATE int *XOR_Arrays(int *a, int *b, int size) {
  /* Variables */
  int *p = (int*) malloc(sizeof(int) * size);
  int i;

  for(i = 0; i < size; i++) {
    if((a[i] && b[i]) || (!a[i] && !b[i]))
      p[i] = 0;
    else
      p[i] = 1;
  }

  return p;
}

/** @brief Gets a binary number and finds it's decimal value
 *
 *  @param n Binary number
 *  @return The decimal value of the binary number
 */
PUBLIC int convertBinaryToDecimal(int n) {
    int decimalNumber = 0, i = 0, remainder;
    while (n!=0)
    {
        remainder = n%10;
        n /= 10;
        decimalNumber += remainder*pow(2,i);
        ++i;
    }

    return decimalNumber;
}

/** @brief Gets two decimal numbers and finds their combined binary value
 *
 *  @param x Decimal number
 *  @param y Decimal number
 *  @return The array of the binary value of the two decimal numbers
 */
PUBLIC int *convertDecimalToBinary(int x, int y) {
  /* Variables */
  int *result = (int*) malloc(sizeof(int) * 4);

  switch(x) {
    case 0: result[0] = 0; result[1] = 0;
      break;
    case 1: result[0] = 0; result[1] = 1;
      break;
    case 2: result[0] = 1; result[1] = 0;
      break;
    case 3: result[0] = 1; result[1] = 1;
  }

  switch(y) {
    case 0: result[2] = 0; result[3] = 0;
      break;
    case 1: result[2] = 0; result[3] = 1;
      break;
    case 2: result[2] = 1; result[3] = 0;
      break;
    case 3: result[2] = 1; result[3] = 1;
  }

  return result;
}

/** @brief Uses the given 4-bit Array (X1Y1Y2X2) to find the value of the S-Box.
 *
 *  @param array The Array
 *  @param left Which S-Box to use
 *  @return The Value of the S-Box
 */
PRIVATE int s_box(int *array, int left) {
  /* Variables */
  int X, Y;

  X = array[0] * 10 + array[3];
  Y = array[1] * 10 + array[2];

  return left ? S0[convertBinaryToDecimal(X)][convertBinaryToDecimal(Y)] :
                S1[convertBinaryToDecimal(X)][convertBinaryToDecimal(Y)];
}

/** @brief Function that uses the key and the 2 S-Boxes to cipher the text.
 *
 *  @param array The  output of the last stage of the SDED Cipher
 *  @param key The key the user gave
 *  @param first Is 1 if this is the first Round of Permutations
 *  @return A 4-bit Array for the next stage of the SDES Cipher
 */
int *function_with_key(int *array, int *key, int first) {
  /* Variables */
  int *returnArray;
  int *k;

/************************************Calculate key*****************************/
  int *p = P10(key);

#ifdef DEBUG
  printf("**********************Function with Key**************************\n");
  printf("P10: "); printArray(p, 10);
#endif

  p = mergeArrays(leftShift(splitArray(p, 10, 1)), 5,
                  leftShift(splitArray(p, 10, 0)), 5);

#ifdef DEBUG
  printf("After Shift 1: "); printArray(p, 10);
#endif

  if(!first)
    p = mergeArrays(leftShift(leftShift(splitArray(p, 10, 1))), 5,
                    leftShift(leftShift(splitArray(p, 10, 0))), 5);

#ifdef DEBUG
  if(!first) {
    printf("After Shift 2: "); printArray(p, 10);
  }
#endif

  k = P8(p);

#ifdef DEBUG
  printf("P8: "); printArray(k, 8);
  if(first) {
    printf("K1: "); printArray(k, 8);
  } else {
    printf("K2: "); printArray(k, 8);
  }
#endif

/******************************************************************************/

  int *L1 = splitArray(array, 8, 1);
  int *R1 = splitArray(array, 8, 0);

  int *xor = XOR_Arrays(expansionPermutation(R1), k, 8);

  // Split Arrays
  int *L2 = splitArray(xor, 8, 1);
  int *R2 = splitArray(xor, 8, 0);

  // Use S-Box
  int *temp = XOR_Arrays(P4(convertDecimalToBinary(s_box(L2, 1),
                                                         s_box(R2, 0))), L1, 4);

  returnArray = mergeArrays(temp, 4, R1, 4);

#ifdef DEBUG

  printf("EP: "); printArray(expansionPermutation(R1), 8);
  printf("XOR 1: "); printArray(XOR_Arrays(expansionPermutation(R1), k, 8), 8);
  printf("S-Box Output 1: %d\n", s_box(L2, 1));
  printf("S-Box Output 2: %d\n", s_box(R2, 0));
  printf("S: "); printArray(convertDecimalToBinary(s_box(L2, 1), s_box(R2, 0)),
                                                                             4);
  printf("P4: "); printArray(P4(convertDecimalToBinary(s_box(L2, 1),
                                                             s_box(R2, 0))), 4);
  printf("XOR 2: "); printArray(temp, 4);
  printf("Result of Function: "); printArray(returnArray, 8);
#endif

  free(p);
  free(k);
  free(L1);
  free(L2);
  free(R1);
  free(R2);
  free(xor);
  free(temp);
  return returnArray;
}

/** @brief Read user Arguments.
 *
 *  @param plaintext The default Plaintext
 *  @param key The default Key
 *  @param argc The size of the arguments Array
 *  @param argv The arguments Array
 *  @return Should return nothing
 */
PRIVATE void readArguments(int plaintext[], int key[], int argc, char **argv) {
  /* Variables */
  int i;

  // Check for 2 arguments
  if(argc == 3) {
    char *temp1 = argv[1];
    char *temp2 = argv[2];

    // Check for size
    if(strlen(temp1) != 8 || strlen(temp2) != 10) {
      printf("Error: Give 2 arguments of size 8 and 10.\n");
      exit(1);
    }

    // Check arguments type, size and data
    for(i = 0; i < 10; i++) {
      // Check type integer
      if((i < 8 && !isdigit(temp1[i])) || !isdigit(temp2[i])) {
        printf("Error: Arguments should be integers.\n");
        exit(2);
      }

      // Convert to integers
      if(i < 8)
        plaintext[i] = temp1[i] - '0';
      key[i] = temp2[i] - '0';

      // Check data
      if((i < 8 && plaintext[i] != 0 && plaintext[i] != 1) ||
         (key[i] != 0 && key[i] != 1)) {
        printf("Error: Arguments data should only be '0' or '1'.\n");
        exit(3);
      }
    }

  } else if(argc != 1) {
    printf("Error: Give 2 arguments of size 8 and 10.\n");
    exit(1);
  }

}

/** @brief Prints the contents of an integer Array.
 *
 *  @param array The Array to print the data of
 *  @param size The size of the Array
 *  @return Should not return
 */
PUBLIC void printArray(int array[], int size) {
  /* Variables */
  int i;

  for(i = 0; i < size; i++)
    printf("%d ", array[i]);
  printf("\n");
}


/** @brief The main function of the program.
 *
 *  @param argc The size of the arguments Array
 *  @param argv The arguments Array
 *  @return Should not return
 */
PUBLIC int main(int argc, char **argv) {
  /* Variables */
  int plaintext[8] = {0,1,0,1,0,0,0,1};
  int key[10] = {0,1,0,1,0,0,1,1,0,0};

  readArguments(plaintext, key, argc, argv);

#ifdef DEBUG
  printf("************************Initial Values***************************\n");
  printf("Plaintext: "); printArray(plaintext, 8);
  printf("Key: "); printArray(key, 10);
  printf("**********************Initial Permutation************************\n");
#endif

  /*********************************************************/
  int *result = finalPermutation(function_with_key(switchArray(function_with_key
                          (initialPermutation(plaintext), key, 1), 8), key, 0));

  printf("CipherText: "); printArray(result, 8);

  free(result);
  return 1;
}

