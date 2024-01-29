#namedtuple-- 
from collections import namedtuple 

mentor=namedtuple('mentor',['name','age','group'])
new_tuple=mentor("murodjon","26","fn7")
#new_tuple,name="farrux" o'zgartitib bo'lmaydi tuple bo'lgani uchun 
print(new_tuple)
        