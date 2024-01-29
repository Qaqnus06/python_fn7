# searching ga linear search / binary search
# sorting ga insertion / buble/ quick sortlar kiradi
# 1 task
# raqamlar = [7, 1, 4, 78, 123 ,45,2,4,5,78,786,46,5,2,8]
# def shunchaki(m):
#  return sorted(m)
# tartib = shunchaki(raqamlar)
# print(tartib) 

#2 task
# matn = "Hello World"
# def teskari(matn):
#   sozlar = matn.split()
#   teskari_matn = ' '.join(i[::-1] 
#     for i in sozlar) 
#   return teskari_matn
# teskari_matn = teskari(matn)
# print(teskari_matn)

#3 task
# List =([891,435])
# def qoyish(royxat):
#  natija = [int(str(x)[0] + str(x%100//10)+str(x%10)) 
#            for x in royxat]   
#  return natija
# natija=qoyish(List)
# print(natija)
#4 Task
sonlar = list(range(1, 51)) 
def tax(sonlar):
 taxmin = [abs(x -25) for x in sonlar]
 kichik = min(taxmin)
 indeks = taxmin.index(kichik)
 return sonlar[indeks]
print(tax(sonlar))