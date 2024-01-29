import random
import time
names=["farrux","asadbek","murodjon"]
majors=["it","kimyo","iqtisod"]


def pe(pe_num):
    result=[]
    for i in range(pe_num):
        person={
            "id":i,
            "name": random.choice(names),
            "majors":random.choice(majors)
        }
        result.append(person)
    return result

def people_gen(pe__num):
    for i in range (pe__num):                                                                                                                 
        person={
            "id":i,
            "name": random.choice(names),
            "majors":random.choice(majors)
        }
time1=time.time()
print(time1)