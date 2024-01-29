import time
import multiprocessing

start=time.perf_counter()


def do_smthresh(son):
    print(f"do_smthresh ....{son}")
    time.sleep(1)
    print(f"do_smthresh finished....{son}")
if  __name__== '__main__':
    process=[]
    for i in range(3):

      p=multiprocessing.Process(target=do_smthresh,args=[i])
      p.start()
      process.append(p)
    for p in process:
      p.join()
finish=time.perf_counter()
print(f"finished in {round(finish-start,2)}")