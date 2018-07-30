#include "sum.h"

int sum(int n){
	int res = 0;
	/*
	 for(int i=1;i<=n;i++){
		res+=i;
	}
	*/
	res=n*(n+1)/2;
	return res;
}

