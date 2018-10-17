#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

#include<stdint.h>
typedef int32_t fp_int;

// Using 17.14 format
#define F (1 << 14)

//Conversions
#define CONVERT_TO_FP(n) (n)*(F)
#define CONVERT_TO_INT(x) (x)/(F) //Rounds towards 0
#define CONVERT_TO_INT_NEAR(x) \
    ((x)<0 ? ((x)-(F)/2)/(F) : ((x) + (F)/2)/(F))

//FP arithmetic
#define FP_ADD(x,y) (x)+(y)  
#define FP_SUB(x,y) (x)-(y)
#define INT_ADD(x,n) (x)+(n)*(F)
#define INT_SUB(x,n) (x)-(n)*(F)
#define FP_MUL(x,y) ((int64_t)(x))*(y)/(F)
#define INT_MUL(x,n) (x)*(n)
#define FP_DIV(x,y) ((int64_t)(x))*(F)/(y)
#define INT_DIV(x,n) (x)/(n)

#endif
