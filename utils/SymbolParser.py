import time


def cust_times(func):
    def wrapper(*args, **kwargs):
        startTime = time.time()
        ret = func(*args, **kwargs)
        endTime = time.time()
        print("Cost time : %f" % (endTime - startTime))
        return ret
    return wrapper
