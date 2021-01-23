print( sum( [ 1 for x in open('data.dat', 'r').read().splitlines() if x.count('0') % 3 == 0 or x.count('1') % 2 == 0 ] ))
