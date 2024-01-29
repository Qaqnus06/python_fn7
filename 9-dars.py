# with open ("sample.txt","w+") as file:
#     file.write("salom")
#print(file.closed)    # fileni yopishda ishlatiladi yani ozi ochadi va yopadi
# from contextlib import contextmanager

# @contextmanager
# def open_file(file,mode):
#     try:
#         f=open(file,mode)
#         return f
#     finally:
#         f.close()
# with open_file("sample.txt", "w+")  as f:
#     f.write("salom dunyo") 
# print(f.close())





# start=time.perf_counter()
# def do_smth():
#     print("reading a file....")
#     time.sleep(1)
#     print("completed reading ...")
# with concurrent.futures.ThreadPoolExecutor()  as executor:
#     list_a(5,4,3,2,1)
#     rec=executor.map(do_smth,list_a)




# thread=[]
# for i in range(30):
#     t=threading.Thread(target=do_smth)
#     t.start()
#     thread.append(t)
# for t in thread:
#     t.join()
# t1=threading.Thread(target=do_smth)
# t2=threading.Thread(target=do_smth)  

# t1.start()
# t2.start()

# t1.join()
# t2.join()

            
# finish=time.perf_counter()
# print(f"Funksiya ishlash tezligi  {round(finish-start,2)}")


























