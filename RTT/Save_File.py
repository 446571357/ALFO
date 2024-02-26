import csv
import os

from xlrd import open_workbook
from xlutils.copy import copy


# 文件父目录
# def get_path(file):
#     path = '/home/zeng/Desktop/attack/Statistic/'
#     file = path + file
#     return file


# 追加一行内容至Excel data=[time,dpid_entry,....]
def add_to_excel(data, file):
    file = file + '.xls'
    f = open_workbook(file)
    row = f.sheet_by_index(0).nrows  # 文件已有行数
    excel = copy(f)
    table = excel.get_sheet(0)  # 获取要操作的工作表
    for i in range(len(data)):  # 追加一行内容
        table.write(row, i, data[i])
    excel.save(file)


# 追加一行内容至txt data=[time,dpid_entry,....]
def add_to_txt(data, path, file):
    if not os.path.exists(path):
        os.makedirs(path)     # 创建父目录
    file = path + file + '.txt'
    with open(file, "a+", newline='') as f:       # with…as… 语句：防止忘记关闭文件
        f.write(str(data))


# 追加一行内容至csv data=[time,dpid_entry,....]
def add_to_csv(data, file):
    file = file + '.csv'
    with open(file, 'a+', newline='') as f:  # newline='': 这个限定插入新数据不会空行，如果没有这个，每次插入数据都会隔行填数据
        csv_write = csv.writer(f)
        csv_write.writerow(data)
