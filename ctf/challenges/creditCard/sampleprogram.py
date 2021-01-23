def func(n):
	x=2*n
	return x%10+x/10
	
def sumcheck(l):
	sumofValue=0
	is_second=0
	for i in range(len(l)-1,-1,-1):
		d = int(l[i])
		if(is_second==1):
			d=d*2
			sumofValue += d/10+d%10
			is_second = (is_second+1)%2
	return sumofValue
	

l="543210******1234".replace('*','0')
num=123456
print(sumcheck(l))


for a in range(10):
	for b in range(10):
		for c in range(10):
			for d in range(10):
				for e in range(10):
					for f in range(10):
						 x=list(l)
						 if((func(a)+b+func(c)+d+func(e)+f)%10==1):
						 	y=str(a)+str(b)+str(c)+str(d)+str(e)+str(f)
						 	x[6:12]=list(y)
						 	if(int(''.join(x))%num==0):
						 		print("CTFlearn{" + ''.join(x) + "}")
