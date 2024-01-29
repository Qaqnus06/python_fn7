# buble_sort      eng sekin ishlaydigan sortlash
#  insertion_sort  bubl_sortdan ko'ra tezroq
my_list=[56,2,45,1,3,4,98,7,456,1,2,12,10]

def quick_sort(list_a):
    length=len(list_a)

    if length<1:  #eng tez sort quick sortdir
        return list_a
    else:
        pivot=list_a.pop()
        left_list=[]
        right_list=[]
        for i in list_a:
        
            if pivot>i:
                right_list.append(i)
            else:
                left_list.append(i)
    return quick_sort(left_list)+[pivot]+quick_sort(right_list)
print(quick_sort(my_list))              