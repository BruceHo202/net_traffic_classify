#!usr/bin/env python  
# -*- coding:utf-8 _*-  
import pickle
import pandas as pd



def readcsv(path):
    with open(path,'rb') as fp:
        content = pd.read_csv(fp)
        return content


def readLine(path):
    with open(path, "ab+") as fp:
        word = str(fp.readline())
    return word


def savefile(path, content):
    with open(path, "ab+") as fp:
        fp.write(content)
        fp.write('\n'.encode())

def readfile(path):
    with open(path, "ab+") as fp:
        content = fp.read()
    return content


def writebunchobj(path, bunchobj):
    with open(path, "wb") as file_obj:
        pickle.dump(bunchobj, file_obj)

def readbunchobj(path):
    with open(path, "rb") as file_obj:
        bunch = pickle.load(file_obj)
    return bunch

